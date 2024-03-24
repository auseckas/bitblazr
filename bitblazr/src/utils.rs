use std::hash::{DefaultHasher, Hash, Hasher};

pub(crate) fn get_hash<T>(obj: T) -> u64
where
    T: Hash,
{
    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish()
}

pub fn vec_to_string<T>(v: Vec<T>) -> String
where
    T: ToString,
{
    let mut s = String::new();

    for e in v.into_iter() {
        if !s.is_empty() {
            s.push_str(", ");
        } else {
            s.push_str("[");
        }
        s.push_str(&e.to_string());
    }
    s.push(']');
    s
}
