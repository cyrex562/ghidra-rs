//! Former home of `ParamListStandardImpl`, the concrete implementor of the old
//! `ParamListStandard` trait.
//!
//! `ghidra.program.model.lang.ParamListStandard` is a concrete Java class, so it is now ported
//! directly as the struct
//! [`ParamListStandard`](crate::program::model::lang::param_list_standard::ParamListStandard);
//! the trait + `*Impl` split this module belonged to is gone. This file holds no items and is
//! kept only because unattended ports do not delete files; it can be removed together with its
//! `mod` line in `lang/mod.rs`.
