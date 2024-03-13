use std::hash::{DefaultHasher, Hash, Hasher};

pub(crate) fn get_hash<T>(obj: T) -> u64
where
    T: Hash,
{
    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish()
}