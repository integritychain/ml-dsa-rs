use crate::algs::check;

mod algs;

pub fn add(left: usize, right: usize) -> usize {
    check();
    left + right
}

#[cfg(test)]
mod tests {
    use crate::algs::check;
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        check();
        assert_eq!(result, 4);
    }
}
