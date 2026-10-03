trait Builder {
    fn set_name(self: Box<Self>, name: &str) -> Box<dyn Builder> {
        let _ = name;
        self
    }
    fn build(&self) -> i32 {
        0
    }
}

struct Empty;
impl Builder for Empty {}

fn main() {
    let b: Box<dyn Builder> = Box::new(Empty);
    let b2 = b.set_name("x");
    println!("{}", b2.build());
}
