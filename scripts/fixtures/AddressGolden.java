// Emits golden values for ghidra.program.model.address.{Address,AddressSpace} straight from a
// real Ghidra install, for ghidra-rs/tests/address_golden.rs to assert against.
//
// Why this exists: the port has ~19.6k tests and not one of them compares against Ghidra. They
// assert what the porter believed, so a faithful-looking translation that is subtly wrong passes
// forever. This closes that for the address arithmetic everything else is built on.
//
// The cases are chosen to hit the Java-to-Rust semantic traps the pattern audit flagged:
//   * Java has no unsigned integers, so Ghidra stores addresses in a signed long and compares
//     them with careful masking. Offsets straddling 0x8000_0000_0000_0000 are where a literal
//     port using signed comparison silently inverts the ordering.
//   * Java arithmetic wraps on overflow; Rust panics in debug and wraps in release. Wrap/no-wrap
//     variants at the space boundary are where that difference becomes visible.
//   * Address spaces smaller than 64 bits truncate, so the boundary is per-space, not per-type.
//
// Build/run via gen_address_fixtures.sh.

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

public final class AddressGolden {

    /** One space under test: name, bit size, addressable unit size. */
    private record Space(String name, int size, int unitSize) {}

    private static final List<String> RECORDS = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        List<Space> spaces = List.of(
                new Space("ram64", 64, 1),
                new Space("ram32", 32, 1),
                new Space("ram16", 16, 1),
                // unitSize > 1: addressable word offsets diverge from byte offsets
                new Space("word32", 32, 2),
                // (64,8) is REJECTED by Ghidra: 2^size * wordsize must fit in 2^64.
                new Space("quad32", 32, 8));

        for (Space s : spaces) {
            // (name, size, unitSize, type, unique) -- the 4-arg overload silently uses
            // unitSize=1, which would compare a 1-byte Java space against a 2/8-byte Rust one.
            AddressSpace space = new GenericAddressSpace(
                    s.name(), s.size(), s.unitSize(), AddressSpace.TYPE_RAM, 0);
            emitSpace(s, space);
            for (long offset : offsetsFor(s.size())) {
                emitAddress(s, space, offset);
                for (long delta : deltas()) {
                    emitArithmetic(s, space, offset, delta);
                }
                for (long other : offsetsFor(s.size())) {
                    emitPair(s, space, offset, other);
                }
            }
        }

        PrintStream out = new PrintStream(System.out, true, "UTF-8");
        out.println("[");
        for (int i = 0; i < RECORDS.size(); i++) {
            out.print("  " + RECORDS.get(i));
            out.println(i + 1 < RECORDS.size() ? "," : "");
        }
        out.println("]");
    }

    /** Offsets clustered on the boundaries where signed/unsigned confusion shows up. */
    private static long[] offsetsFor(int size) {
        if (size >= 64) {
            return new long[] {
                0L, 1L, 0x7FL, 0x80L,
                0x7FFF_FFFFL, 0x8000_0000L, 0xFFFF_FFFFL,
                0x7FFF_FFFF_FFFF_FFFFL,          // largest positive signed long
                0x8000_0000_0000_0000L,          // negative as signed, huge as unsigned
                0xFFFF_FFFF_FFFF_FFFEL,
                -1L                              // == unsigned 0xFFFF...FF, the space max
            };
        }
        long max = (size == 32) ? 0xFFFF_FFFFL : 0xFFFFL;
        return new long[] {0L, 1L, 0x7FL, 0x80L, max / 2, (max / 2) + 1, max - 1, max};
    }

    private static long[] deltas() {
        return new long[] {0L, 1L, -1L, 2L, -2L, 0x1000L, -0x1000L, Long.MAX_VALUE, Long.MIN_VALUE};
    }

    private static void emitSpace(Space s, AddressSpace space) {
        RECORDS.add(obj(
                kv("kind", "space"),
                kv("space", s.name()),
                num("size", s.size()),
                num("unit_size", space.getAddressableUnitSize()),
                num("min_offset", space.getMinAddress().getOffset()),
                num("max_offset", space.getMaxAddress().getOffset()),
                bool("signed", space.hasSignedOffset())));
    }

    private static void emitAddress(Space s, AddressSpace space, long offset) {
        Address a = space.getAddress(offset);
        RECORDS.add(obj(
                kv("kind", "address"),
                kv("space", s.name()),
                num("offset", offset),
                num("stored_offset", a.getOffset()),
                num("unsigned_offset", a.getUnsignedOffset()),
                num("word_offset", a.getAddressableWordOffset()),
                kv("to_string", a.toString())));
    }

    private static void emitArithmetic(Space s, AddressSpace space, long offset, long delta) {
        Address a = space.getAddress(offset);

        RECORDS.add(obj(
                kv("kind", "add_wrap"),
                kv("space", s.name()),
                num("offset", offset),
                num("delta", delta),
                num("result", a.addWrap(delta).getOffset())));

        RECORDS.add(obj(
                kv("kind", "subtract_wrap"),
                kv("space", s.name()),
                num("offset", offset),
                num("delta", delta),
                num("result", a.subtractWrap(delta).getOffset())));

        RECORDS.add(withOutcome("add_no_wrap", s, offset, delta,
                () -> a.addNoWrap(delta).getOffset()));
        RECORDS.add(withOutcome("subtract_no_wrap", s, offset, delta,
                () -> a.subtractNoWrap(delta).getOffset()));
    }

    private static void emitPair(Space s, AddressSpace space, long a, long b) {
        Address x = space.getAddress(a);
        Address y = space.getAddress(b);
        RECORDS.add(obj(
                kv("kind", "pair"),
                kv("space", s.name()),
                num("a", a),
                num("b", b),
                // Ghidra compares addresses as UNSIGNED offsets; a signed comparison in the port
                // would invert every pair straddling 0x8000_0000_0000_0000.
                num("compare", Integer.signum(x.compareTo(y))),
                num("subtract", x.subtract(y)),
                bool("is_successor", y.isSuccessor(x))));
    }

    /** Records either a value or the exception type, so the port's Result must agree too. */
    private static String withOutcome(String kind, Space s, long offset, long delta,
            ThrowingLongSupplier op) {
        try {
            return obj(
                    kv("kind", kind),
                    kv("space", s.name()),
                    num("offset", offset),
                    num("delta", delta),
                    kv("outcome", "ok"),
                    num("result", op.getAsLong()));
        } catch (AddressOverflowException e) {
            return obj(kv("kind", kind), kv("space", s.name()), num("offset", offset),
                    num("delta", delta), kv("outcome", "overflow"));
        } catch (AddressOutOfBoundsException e) {
            return obj(kv("kind", kind), kv("space", s.name()), num("offset", offset),
                    num("delta", delta), kv("outcome", "out_of_bounds"));
        }
    }

    @FunctionalInterface
    private interface ThrowingLongSupplier {
        long getAsLong() throws AddressOverflowException;
    }

    // --- tiny JSON writer, to avoid pulling a dependency into the harness ---

    private static String obj(String... fields) {
        return "{" + String.join(", ", fields) + "}";
    }

    private static String kv(String k, String v) {
        return "\"" + k + "\": \"" + escape(v) + "\"";
    }

    private static String num(String k, long v) {
        return "\"" + k + "\": " + v;
    }

    private static String bool(String k, boolean v) {
        return "\"" + k + "\": " + v;
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
