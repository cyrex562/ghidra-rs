//! Derive macros for `ghidra-rs`.
//!
//! # `#[derive(StructureMapped)]`
//!
//! Replaces the Java reflection that drives Ghidra's golang structure mapping
//! (`ghidra.app.util.bin.format.golang.structmapping`). Java discovers `@StructureMapping`,
//! `@FieldMapping`, `@FieldOutput`, `@Markup`, `@MarkupReference`, `@EOLComment`,
//! `@PlateComment`, `@ContextField` and `@AfterStructureRead` annotations at run time through
//! `java.lang.reflect`; this derive reads the equivalent Rust attributes at compile time and
//! emits a static `StructureMappingDescriptor` table (field names, lengths, signedness, typed
//! read/assign function pointers, markup getters) plus the instance constructor that performs
//! `@ContextField` injection.
//!
//! The generated code refers to `crate::format::golang::structmapping`, so the derive is only
//! usable inside the `ghidra-rs` crate itself.
//!
//! ## Type attributes: `#[structure_mapping(...)]`
//!
//! | key | Java equivalent |
//! |---|---|
//! | `structure_name = "a"` or `structure_name = ["a", "b"]` | `@StructureMapping(structureName = ...)` (required) |
//! | `reader` | `implements StructureReader` (calls `StructureReader::read_structure`) |
//! | `verifier` | `implements StructureVerifier` (calls `StructureVerifier::is_valid`) |
//! | `structure_markup` | `implements StructureMarkup` |
//! | `after_read = method` (repeatable) | `@AfterStructureRead` method |
//! | `markup = method` (repeatable) | `@Markup` getter method |
//! | `plate_comment` / `plate_comment = method` | type-level `@PlateComment` (default: `Display`) |
//!
//! ## Field attributes
//!
//! | attribute | Java equivalent |
//! |---|---|
//! | `#[field_mapping(field_name = .., optional, present_when = "..", setter = method, read_func = path, length = N, signedness = Signed/Unsigned)]` | `@FieldMapping` |
//! | `#[field_output(ordinal = N, offset = N, data_type_name = "..", variable_length, getter = method, output_func = path)]` | `@FieldOutput` |
//! | `#[markup]` | `@Markup` on a field |
//! | `#[markup_reference]` / `#[markup_reference(method)]` | `@MarkupReference` |
//! | `#[eol_comment]` / `#[eol_comment(method)]` | `@EOLComment` |
//! | `#[plate_comment]` / `#[plate_comment(method)]` | `@PlateComment` on a field |
//! | `#[context_field]` | `@ContextField` |
//!
//! Java's `@FieldMapping` without an explicit `fieldName` searches for the Java field name; a
//! Rust field `ptr_to_this` is searched for as `ptrToThis` (lower camel case), which is what the
//! Java field was called. Java auto-detects a `set<Field>` setter by reflection; here a setter is
//! named explicitly with `setter = method`.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, Data, DeriveInput, Expr, ExprArray, ExprLit, Fields, GenericArgument, Ident,
    Lit, LitStr, Meta, Path, PathArguments, Token, Type,
};

/// Derives `StructureMapped` for a struct. See the crate docs for the accepted attributes.
#[proc_macro_derive(
    StructureMapped,
    attributes(
        structure_mapping,
        field_mapping,
        field_output,
        markup,
        markup_reference,
        eol_comment,
        plate_comment,
        context_field
    )
)]
pub fn derive_structure_mapped(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[derive(Default)]
struct TypeAttrs {
    structure_names: Vec<LitStr>,
    reader: bool,
    verifier: bool,
    structure_markup: bool,
    after_read: Vec<Ident>,
    markup: Vec<Ident>,
    plate_comment: Option<Option<Ident>>,
}

#[derive(Default)]
struct FieldMappingAttrs {
    field_names: Vec<LitStr>,
    optional: bool,
    present_when: Option<LitStr>,
    setter: Option<Ident>,
    read_func: Option<Path>,
    length: Option<i32>,
    signedness: Option<Ident>,
}

#[derive(Default)]
struct FieldOutputAttrs {
    ordinal: Option<i32>,
    offset: Option<i32>,
    data_type_name: Option<LitStr>,
    variable_length: bool,
    getter: Option<Ident>,
    output_func: Option<Path>,
}

#[derive(Default)]
struct FieldAttrs {
    mapping: Option<FieldMappingAttrs>,
    output: Option<FieldOutputAttrs>,
    markup: bool,
    markup_reference: Option<Option<Ident>>,
    eol_comment: Option<Option<Ident>>,
    plate_comment: Option<Option<Ident>>,
    context_field: bool,
}

/// Java primitive widths the structure mapper knows how to read (`ReflectionHelper.NUM_CLASSES`).
#[derive(Clone, Copy)]
enum Prim {
    Long,
    Int,
    Short,
    Byte,
}

#[derive(Clone, Copy)]
enum Kind {
    Primitive(Prim),
    PrimitiveArray(Prim),
    Nested,
}

fn prim_of(ty: &Type) -> Option<Prim> {
    let Type::Path(tp) = ty else { return None };
    if tp.qself.is_some() || tp.path.segments.len() != 1 {
        return None;
    }
    match tp.path.segments[0].ident.to_string().as_str() {
        "i64" | "u64" => Some(Prim::Long),
        "i32" | "u32" => Some(Prim::Int),
        "i16" | "u16" => Some(Prim::Short),
        "i8" | "u8" => Some(Prim::Byte),
        _ => None,
    }
}

fn array_elem_prim(ty: &Type) -> Option<Prim> {
    match ty {
        Type::Array(a) => prim_of(&a.elem),
        Type::Path(tp) => {
            let seg = tp.path.segments.last()?;
            if seg.ident != "Vec" {
                return None;
            }
            let PathArguments::AngleBracketed(args) = &seg.arguments else { return None };
            match args.args.first()? {
                GenericArgument::Type(t) => prim_of(t),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `Option<X>` -> `X`: a nullable nested structure field is read as `Some(value)`.
fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(tp) = ty else { return None };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else { return None };
    match args.args.first()? {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    }
}

fn is_structure_context(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => tp.path.segments.last().is_some_and(|s| s.ident == "StructureContext"),
        _ => false,
    }
}

fn kind_of(ty: &Type) -> Kind {
    if let Some(p) = prim_of(ty) {
        Kind::Primitive(p)
    }
    else if let Some(p) = array_elem_prim(ty) {
        Kind::PrimitiveArray(p)
    }
    else {
        Kind::Nested
    }
}

fn prim_tokens(p: Prim) -> TokenStream2 {
    match p {
        Prim::Long => quote!(__sm::PrimitiveKind::Long),
        Prim::Int => quote!(__sm::PrimitiveKind::Int),
        Prim::Short => quote!(__sm::PrimitiveKind::Short),
        Prim::Byte => quote!(__sm::PrimitiveKind::Byte),
    }
}

/// `ptr_to_this` -> `ptrToThis`, `r#type` -> `type`.
fn java_field_name(ident: &Ident) -> String {
    let s = ident.to_string();
    let s = s.strip_prefix("r#").unwrap_or(&s);
    let mut out = String::new();
    let mut upper_next = false;
    for (i, c) in s.chars().enumerate() {
        if c == '_' && i > 0 {
            upper_next = true;
        }
        else if upper_next {
            out.extend(c.to_uppercase());
            upper_next = false;
        }
        else {
            out.push(c);
        }
    }
    out
}

fn lit_int(expr: &Expr) -> syn::Result<i32> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) => i.base10_parse(),
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => Ok(-lit_int(&u.expr)?),
        _ => Err(syn::Error::new(expr.span(), "expected an integer literal")),
    }
}

fn lit_strs(expr: &Expr) -> syn::Result<Vec<LitStr>> {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => Ok(vec![s.clone()]),
        Expr::Array(ExprArray { elems, .. }) => elems
            .iter()
            .map(|e| match e {
                Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => Ok(s.clone()),
                _ => Err(syn::Error::new(e.span(), "expected a string literal")),
            })
            .collect(),
        _ => Err(syn::Error::new(expr.span(), "expected a string literal or an array of them")),
    }
}

fn parse_type_attrs(input: &DeriveInput) -> syn::Result<TypeAttrs> {
    let mut attrs = TypeAttrs::default();
    let mut seen = false;
    for attr in &input.attrs {
        if !attr.path().is_ident("structure_mapping") {
            continue;
        }
        seen = true;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("structure_name") {
                let e: Expr = meta.value()?.parse()?;
                attrs.structure_names = lit_strs(&e)?;
            }
            else if meta.path.is_ident("reader") {
                attrs.reader = true;
            }
            else if meta.path.is_ident("verifier") {
                attrs.verifier = true;
            }
            else if meta.path.is_ident("structure_markup") {
                attrs.structure_markup = true;
            }
            else if meta.path.is_ident("after_read") {
                attrs.after_read.push(meta.value()?.parse()?);
            }
            else if meta.path.is_ident("markup") {
                attrs.markup.push(meta.value()?.parse()?);
            }
            else if meta.path.is_ident("plate_comment") {
                if meta.input.peek(Token![=]) {
                    attrs.plate_comment = Some(Some(meta.value()?.parse()?));
                }
                else {
                    attrs.plate_comment = Some(None);
                }
            }
            else {
                return Err(meta.error("unknown structure_mapping key"));
            }
            Ok(())
        })?;
    }
    if !seen || attrs.structure_names.is_empty() {
        return Err(syn::Error::new(
            input.ident.span(),
            "Missing #[structure_mapping(structure_name = ...)] on a StructureMapped type",
        ));
    }
    Ok(attrs)
}

/// Parses the optional single-identifier argument of `#[eol_comment(getter)]`-style attributes.
fn optional_getter(attr: &syn::Attribute) -> syn::Result<Option<Ident>> {
    match &attr.meta {
        Meta::Path(_) => Ok(None),
        Meta::List(list) => {
            let idents: Punctuated<Ident, Token![,]> =
                list.parse_args_with(Punctuated::parse_terminated)?;
            match idents.len() {
                0 => Ok(None),
                1 => Ok(idents.into_iter().next()),
                _ => Err(syn::Error::new(list.span(), "expected at most one getter method name")),
            }
        }
        Meta::NameValue(nv) => Err(syn::Error::new(nv.span(), "use attr(getter), not attr = ..")),
    }
}

fn parse_field_attrs(field: &syn::Field) -> syn::Result<FieldAttrs> {
    let mut fa = FieldAttrs::default();
    for attr in &field.attrs {
        let path = attr.path();
        if path.is_ident("field_mapping") {
            let mut fm = FieldMappingAttrs::default();
            if !matches!(attr.meta, Meta::Path(_)) {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("field_name") {
                        let e: Expr = meta.value()?.parse()?;
                        fm.field_names = lit_strs(&e)?;
                    }
                    else if meta.path.is_ident("optional") {
                        fm.optional = true;
                    }
                    else if meta.path.is_ident("present_when") {
                        fm.present_when = Some(meta.value()?.parse()?);
                    }
                    else if meta.path.is_ident("setter") {
                        fm.setter = Some(meta.value()?.parse()?);
                    }
                    else if meta.path.is_ident("read_func") {
                        fm.read_func = Some(meta.value()?.parse()?);
                    }
                    else if meta.path.is_ident("length") {
                        let e: Expr = meta.value()?.parse()?;
                        fm.length = Some(lit_int(&e)?);
                    }
                    else if meta.path.is_ident("signedness") {
                        fm.signedness = Some(meta.value()?.parse()?);
                    }
                    else {
                        return Err(meta.error("unknown field_mapping key"));
                    }
                    Ok(())
                })?;
            }
            fa.mapping = Some(fm);
        }
        else if path.is_ident("field_output") {
            let mut fo = FieldOutputAttrs::default();
            if !matches!(attr.meta, Meta::Path(_)) {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("ordinal") {
                        let e: Expr = meta.value()?.parse()?;
                        fo.ordinal = Some(lit_int(&e)?);
                    }
                    else if meta.path.is_ident("offset") {
                        let e: Expr = meta.value()?.parse()?;
                        fo.offset = Some(lit_int(&e)?);
                    }
                    else if meta.path.is_ident("data_type_name") {
                        fo.data_type_name = Some(meta.value()?.parse()?);
                    }
                    else if meta.path.is_ident("variable_length") {
                        fo.variable_length = true;
                    }
                    else if meta.path.is_ident("getter") {
                        fo.getter = Some(meta.value()?.parse()?);
                    }
                    else if meta.path.is_ident("output_func") {
                        fo.output_func = Some(meta.value()?.parse()?);
                    }
                    else {
                        return Err(meta.error("unknown field_output key"));
                    }
                    Ok(())
                })?;
            }
            fa.output = Some(fo);
        }
        else if path.is_ident("markup") {
            fa.markup = true;
        }
        else if path.is_ident("markup_reference") {
            fa.markup_reference = Some(optional_getter(attr)?);
        }
        else if path.is_ident("eol_comment") {
            fa.eol_comment = Some(optional_getter(attr)?);
        }
        else if path.is_ident("plate_comment") {
            fa.plate_comment = Some(optional_getter(attr)?);
        }
        else if path.is_ident("context_field") {
            fa.context_field = true;
        }
    }
    Ok(fa)
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "StructureMapped cannot be derived for generic types",
        ));
    }
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(name.span(), "StructureMapped can only be derived for structs"));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new(name.span(), "StructureMapped requires named fields"));
    };
    let tattrs = parse_type_attrs(input)?;

    let mut field_descs = Vec::new();
    let mut ctor_fields = Vec::new();
    let mut structure_context_field: Option<Ident> = None;

    for field in &named.named {
        let fident = field.ident.clone().expect("named field");
        let fty = &field.ty;
        let fa = parse_field_attrs(field)?;

        // ---- constructor / @ContextField injection
        if fa.context_field {
            if is_structure_context(fty) {
                if structure_context_field.is_some() {
                    return Err(syn::Error::new(fident.span(), "more than one StructureContext field"));
                }
                structure_context_field = Some(fident.clone());
                ctor_fields.push(quote!(#fident: __ctx));
            }
            else {
                ctor_fields.push(quote!(#fident: __mapper.get_context_value::<#fty>(#name::__SM_TYPE_NAME, stringify!(#fident))?));
            }
        }
        else {
            ctor_fields.push(quote!(#fident: ::core::default::Default::default()));
        }

        if fa.mapping.is_none() && fa.output.is_none() {
            if fa.markup || fa.markup_reference.is_some() || fa.eol_comment.is_some() || fa.plate_comment.is_some() {
                return Err(syn::Error::new(
                    fident.span(),
                    "markup/comment attributes require #[field_mapping] or #[field_output]",
                ));
            }
            continue;
        }

        let kind = kind_of(fty);
        let java_name = java_field_name(&fident);
        let fname_str = fident.to_string();

        let kind_tokens = match kind {
            Kind::Primitive(p) => {
                let p = prim_tokens(p);
                quote!(__sm::FieldValueKind::Primitive(#p))
            }
            Kind::PrimitiveArray(p) => {
                let p = prim_tokens(p);
                quote!(__sm::FieldValueKind::PrimitiveArray(#p))
            }
            Kind::Nested => quote!(__sm::FieldValueKind::StructureMapped),
        };

        // ---- @FieldMapping
        let (mapping_tokens, read_func_tokens, setter) = match &fa.mapping {
            Some(fm) => {
                // empty when not given, as Java's `fieldName() default ""`; the search then uses
                // the field's own (Java) name, carried in `search_name`
                let names: Vec<LitStr> = fm.field_names.clone();
                let optional = fm.optional;
                let present_when = fm
                    .present_when
                    .clone()
                    .unwrap_or_else(|| LitStr::new("", Span::call_site()));
                let length = fm.length.unwrap_or(-1);
                let signedness = match &fm.signedness {
                    None => quote!(__sm::Signedness::Unspecified),
                    Some(i) if i == "Signed" => quote!(__sm::Signedness::Signed),
                    Some(i) if i == "Unsigned" => quote!(__sm::Signedness::Unsigned),
                    Some(i) if i == "Unspecified" => quote!(__sm::Signedness::Unspecified),
                    Some(i) => return Err(syn::Error::new(i.span(), "expected Signed, Unsigned or Unspecified")),
                };
                let rf = match &fm.read_func {
                    Some(f) => quote!(::core::option::Option::Some(#f as __sm::FieldReadFn<#name>)),
                    None => quote!(::core::option::Option::None),
                };
                (
                    quote!(::core::option::Option::Some(__sm::FieldMappingAttr {
                        field_names: &[#(#names),*],
                        optional: #optional,
                        present_when: #present_when,
                        length: #length,
                        signedness: #signedness,
                    })),
                    rf,
                    fm.setter.clone(),
                )
            }
            None => (
                quote!(::core::option::Option::None),
                quote!(::core::option::Option::None),
                None,
            ),
        };
        let search_name = match &fa.mapping {
            Some(fm) if !fm.field_names.is_empty() => fm.field_names[0].value(),
            _ => java_name.clone(),
        };

        // ---- read (nested structure mapped types) and assign
        let (read_ty, wrap) = match option_inner(fty) {
            Some(inner) => (inner, quote!(::core::option::Option::Some)),
            None => (fty, quote!()),
        };
        let read_nested = match kind {
            Kind::Nested => quote!(::core::option::Option::Some(
                (|__fc: &mut __sm::FieldContext<'_, #name>, __mapper: &__sm::DataTypeMapper|
                    -> ::std::io::Result<__sm::FieldValue> {
                    let __dt = __fc.dtc_data_type();
                    let __v: #fty = #wrap(__mapper.read_structure_with::<#read_ty>(__dt, __fc.reader_mut()?)?);
                    ::std::io::Result::Ok(__sm::FieldValue::Object(::std::boxed::Box::new(__v)))
                }) as __sm::FieldReadFn<#name>
            )),
            _ => quote!(::core::option::Option::None),
        };
        let convert = match kind {
            Kind::Primitive(_) => quote!(let __v: #fty = __value.into_primitive(stringify!(#fident))? as #fty;),
            _ => quote!(let __v: #fty = __value.downcast::<#fty>(stringify!(#fident))?;),
        };
        let store = match &setter {
            Some(s) => quote!(__sm::IntoIoResult::into_io_result(__obj.#s(__v))?;),
            None => quote!(__obj.#fident = __v;),
        };
        let assign = quote!(
            (|__obj: &mut #name, __value: __sm::FieldValue| -> ::std::io::Result<()> {
                #convert
                #store
                ::std::io::Result::Ok(())
            }) as __sm::FieldAssignFn<#name>
        );

        // ---- markup funcs
        let markup_nested = if fa.markup {
            quote!(::core::option::Option::Some(
                (|__obj: &#name, __session: &mut __sm::MarkupSession<'_>| -> ::std::io::Result<()> {
                    __sm::MarkupTarget::markup_target(&__obj.#fident, __session, true)
                }) as __sm::MarkupGetterFn<#name>
            ))
        }
        else {
            quote!(::core::option::Option::None)
        };
        let comment_fn = |g: &Option<Option<Ident>>| match g {
            None => quote!(::core::option::Option::None),
            Some(getter) => {
                let value = match getter {
                    Some(m) => quote!(__obj.#m()),
                    None => quote!(&__obj.#fident),
                };
                quote!(::core::option::Option::Some(
                    (|__obj: &#name| -> ::std::io::Result<::core::option::Option<::std::string::String>> {
                        __sm::CommentValue::comment_text(#value)
                    }) as __sm::CommentGetterFn<#name>
                ))
            }
        };
        let plate_comment = comment_fn(&fa.plate_comment);
        let eol_comment = comment_fn(&fa.eol_comment);
        let markup_reference = match &fa.markup_reference {
            None => quote!(::core::option::Option::None),
            Some(getter) => {
                let value = match getter {
                    Some(m) => quote!(__obj.#m()),
                    None => quote!(&__obj.#fident),
                };
                quote!(::core::option::Option::Some(
                    (|__obj: &#name| -> ::std::io::Result<::core::option::Option<__sm::Address>> {
                        __sm::ReferenceTarget::reference_address(#value)
                    }) as __sm::ReferenceGetterFn<#name>
                ))
            }
        };

        // ---- @FieldOutput
        let output_tokens = match &fa.output {
            None => quote!(::core::option::Option::None),
            Some(fo) => {
                let ordinal = fo.ordinal.unwrap_or(-1);
                let offset = fo.offset.unwrap_or(-1);
                let dtn = fo
                    .data_type_name
                    .clone()
                    .unwrap_or_else(|| LitStr::new("", Span::call_site()));
                let variable_length = fo.variable_length;
                let getter = match &fo.getter {
                    Some(g) => quote!(::core::option::Option::Some(
                        (|__obj: &#name| -> ::std::io::Result<::core::option::Option<__sm::OutputDataType>> {
                            __sm::IntoOutputDataType::into_output_data_type(__obj.#g())
                        }) as __sm::OutputGetterFn<#name>
                    )),
                    None => quote!(::core::option::Option::None),
                };
                let output_func = match &fo.output_func {
                    Some(f) => quote!(::core::option::Option::Some(#f as __sm::FieldOutputFn<#name>)),
                    None => quote!(::core::option::Option::None),
                };
                quote!(::core::option::Option::Some(__sm::FieldOutputAttr {
                    ordinal: #ordinal,
                    offset: #offset,
                    data_type_name: #dtn,
                    is_variable_length: #variable_length,
                    getter: #getter,
                    output_func: #output_func,
                }))
            }
        };
        let nested_data_type = match (kind, &fa.output) {
            (Kind::Nested, Some(_)) => quote!(::core::option::Option::Some(
                (|__obj: &#name, __mapper: &__sm::DataTypeMapper|
                    -> ::std::io::Result<::core::option::Option<::std::sync::Arc<dyn __sm::DataType>>> {
                    __sm::NestedStructure::nested_structure_data_type(&__obj.#fident, __mapper)
                }) as __sm::NestedDataTypeFn<#name>
            )),
            _ => quote!(::core::option::Option::None),
        };
        let array_len = match kind {
            Kind::PrimitiveArray(_) => quote!(::core::option::Option::Some(
                (|__obj: &#name| -> usize { __obj.#fident.len() }) as __sm::ArrayLenFn<#name>
            )),
            _ => quote!(::core::option::Option::None),
        };

        field_descs.push(quote!(__sm::FieldDescriptor::<#name> {
            name: #fname_str,
            search_name: #search_name,
            kind: #kind_tokens,
            mapping: #mapping_tokens,
            output: #output_tokens,
            read_func: #read_func_tokens,
            read_nested: #read_nested,
            assign: #assign,
            markup_nested: #markup_nested,
            plate_comment: #plate_comment,
            eol_comment: #eol_comment,
            markup_reference: #markup_reference,
            nested_data_type: #nested_data_type,
            array_len: #array_len,
        }));
    }

    let type_name_str = name.to_string();
    let structure_names = &tattrs.structure_names;
    let is_reader = tattrs.reader;
    let after_read = tattrs.after_read.iter().map(|m| {
        quote!((|__obj: &mut #name| -> ::std::io::Result<()> {
            __sm::IntoIoResult::into_io_result(__obj.#m())
        }) as __sm::AfterReadFn<#name>)
    });
    let markup_getters = tattrs.markup.iter().map(|m| {
        quote!((|__obj: &#name, __session: &mut __sm::MarkupSession<'_>| -> ::std::io::Result<()> {
            __sm::MarkupTarget::markup_target(__obj.#m(), __session, false)
        }) as __sm::MarkupGetterFn<#name>)
    });
    let type_plate_comment = match &tattrs.plate_comment {
        None => quote!(::core::option::Option::None),
        Some(g) => {
            let value = match g {
                Some(m) => quote!(__obj.#m()),
                None => quote!(::std::string::ToString::to_string(__obj)),
            };
            quote!(::core::option::Option::Some(
                (|__obj: &#name| -> ::std::io::Result<::core::option::Option<::std::string::String>> {
                    __sm::CommentValue::comment_text(#value)
                }) as __sm::CommentGetterFn<#name>
            ))
        }
    };
    let read_structure = if is_reader {
        quote!(::core::option::Option::Some(
            (|__obj: &mut #name, __reader: &mut dyn __sm::BinaryReader, __mapper: &__sm::DataTypeMapper|
                -> ::std::io::Result<()> {
                <#name as __sm::StructureReader>::read_structure(__obj, __reader, __mapper)
            }) as __sm::ReadStructureFn<#name>
        ))
    }
    else {
        quote!(::core::option::Option::None)
    };
    let is_valid = if tattrs.verifier {
        quote!(::core::option::Option::Some(
            (|__obj: &#name| -> bool { <#name as __sm::StructureVerifier>::is_valid(__obj) }) as fn(&#name) -> bool
        ))
    }
    else {
        quote!(::core::option::Option::None)
    };
    let structure_markup = if tattrs.structure_markup {
        quote!(::core::option::Option::Some(__sm::StructureMarkupHooks::<#name> {
            structure_label: (|__obj: &#name| <#name as __sm::StructureMarkup>::structure_label(__obj))
                as fn(&#name) -> ::std::io::Result<::core::option::Option<::std::string::String>>,
            structure_namespace: (|__obj: &#name| <#name as __sm::StructureMarkup>::structure_namespace(__obj))
                as fn(&#name) -> ::std::io::Result<::core::option::Option<::std::string::String>>,
            additional_markup: (|__obj: &#name, __session: &mut __sm::MarkupSession<'_>|
                <#name as __sm::StructureMarkup>::additional_markup(__obj, __session))
                as __sm::MarkupGetterFn<#name>,
            external_instances_to_markup: (|__obj: &#name, __session: &mut __sm::MarkupSession<'_>|
                -> ::std::io::Result<()> {
                for __item in <#name as __sm::StructureMarkup>::external_instances_to_markup(__obj)? {
                    __item.markup_item(__session, false)?;
                }
                ::std::io::Result::Ok(())
            }) as __sm::MarkupGetterFn<#name>,
        }))
    }
    else {
        quote!(::core::option::Option::None)
    };

    let structure_context_accessor = match &structure_context_field {
        Some(f) => quote!(::core::option::Option::Some(&self.#f)),
        None => quote!(::core::option::Option::None),
    };

    let desc_ident = format_ident!("__SM_DESCRIPTOR_{}", name);

    Ok(quote! {
        const _: () = {
            use crate::format::golang::structmapping::structure_mapped::__private as __sm;

            impl #name {
                #[doc(hidden)]
                pub const __SM_TYPE_NAME: &'static str = #type_name_str;
            }

            #[allow(non_upper_case_globals)]
            static #desc_ident: __sm::StructureMappingDescriptor<#name> = __sm::StructureMappingDescriptor {
                type_name: #type_name_str,
                structure_names: &[#(#structure_names),*],
                is_structure_reader: #is_reader,
                fields: &[#(#field_descs),*],
                after_read: &[#(#after_read),*],
                markup_getters: &[#(#markup_getters),*],
                plate_comment: #type_plate_comment,
                read_structure: #read_structure,
                is_valid: #is_valid,
                structure_markup: #structure_markup,
            };

            impl __sm::StructureMapped for #name {
                fn descriptor() -> &'static __sm::StructureMappingDescriptor<Self> {
                    &#desc_ident
                }

                fn create_instance(
                    __ctx: __sm::StructureContext<Self>,
                    __mapper: &__sm::DataTypeMapper,
                ) -> ::std::io::Result<Self> {
                    let _ = &__mapper;
                    ::std::io::Result::Ok(#name { #(#ctor_fields),* })
                }

                fn structure_context(&self) -> ::core::option::Option<&__sm::StructureContext<Self>> {
                    #structure_context_accessor
                }
            }

            impl __sm::MarkupTarget for &#name {
                fn markup_target(self, __session: &mut __sm::MarkupSession<'_>, __nested: bool) -> ::std::io::Result<()> {
                    __session.markup_instance(self, __nested)
                }
            }

            impl __sm::MarkupTarget for #name {
                fn markup_target(self, __session: &mut __sm::MarkupSession<'_>, __nested: bool) -> ::std::io::Result<()> {
                    __session.markup_instance(&self, __nested)
                }
            }

            impl __sm::ReferenceTarget for &#name {
                fn reference_address(self) -> ::std::io::Result<::core::option::Option<__sm::Address>> {
                    ::std::io::Result::Ok(
                        __sm::StructureMapped::structure_context(self).map(|__c| __c.get_structure_address()),
                    )
                }
            }

            impl __sm::ReferenceTarget for #name {
                fn reference_address(self) -> ::std::io::Result<::core::option::Option<__sm::Address>> {
                    __sm::ReferenceTarget::reference_address(&self)
                }
            }

            impl __sm::NestedStructure for #name {
                fn nested_structure_data_type(
                    &self,
                    __mapper: &__sm::DataTypeMapper,
                ) -> ::std::io::Result<::core::option::Option<::std::sync::Arc<dyn __sm::DataType>>> {
                    __sm::nested_structure_data_type_of(self, __mapper)
                }
            }
        };
    })
}
