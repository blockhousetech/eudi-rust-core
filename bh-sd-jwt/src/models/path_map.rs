// Copyright (C) 2020-2026  The Blockhouse Technology Limited (TBTL).
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
// License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::collections::{btree_map::Entry, BTreeMap};

use bherror::Error;

use super::{DecodingResult, JsonNodePathSegment};
use crate::DecodingError;

type Key = String;
type Index = u32;

#[derive(Debug)]
pub(crate) struct PathMap<T> {
    value: Option<T>,
    children: Children<T>,
}

impl<T> Default for PathMap<T> {
    fn default() -> Self {
        Self {
            value: None,
            children: Children::None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum Children<T> {
    None,
    Object(PathMapObject<T>),
    Array(PathMapArray<T>),
}

impl<T> PathMap<T> {
    pub(crate) fn is_empty_leaf(&self) -> bool {
        self.value.is_none()
            && match &self.children {
                Children::None => true,
                Children::Object(path_map_object) => path_map_object.0.is_empty(),
                Children::Array(path_map_array) => path_map_array.0.is_empty(),
            }
    }

    pub(crate) fn insert_value(&mut self, value: T) {
        assert!(
            self.value.is_none(),
            "implementation error: insert_value called on non-empty map"
        );
        self.value = Some(value);
    }

    pub(crate) fn traverse_path<'a, 'p>(
        &'a self,
        mut path: impl Iterator<Item = JsonNodePathSegment<'p>>,
        mut visit_value: impl FnMut(&'a T),
    ) -> Result<(), ()> {
        if let Some(value) = &self.value {
            visit_value(value);
        }
        match &self.children {
            Children::None => {
                if path.next().is_none() {
                    Ok(())
                } else {
                    Err(())
                }
            }
            Children::Object(path_map_object) => path_map_object.traverse_path(path, visit_value),
            Children::Array(path_map_array) => path_map_array.traverse_path(path, visit_value),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PathMapObject<T>(BTreeMap<Key, PathMap<T>>);

impl<T> Default for PathMapObject<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[derive(Debug)]
pub(crate) struct PathMapArray<T>(BTreeMap<Index, PathMap<T>>);

impl<T> Default for PathMapArray<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> PathMapObject<T> {
    pub(crate) fn insert_key(
        &mut self,
        key: Key,
        child: PathMap<T>,
    ) -> DecodingResult<&mut PathMap<T>> {
        match self.0.entry(key) {
            Entry::Occupied(entry) => Err(Error::root(DecodingError::DuplicateClaimName(
                entry.key().to_owned(),
            ))),
            Entry::Vacant(entry) => Ok(entry.insert(child)),
        }
    }

    pub(crate) fn finish_subtree(self) -> PathMap<T> {
        PathMap {
            value: None,
            children: Children::Object(self),
        }
    }

    pub(crate) fn traverse_path<'a, 'p>(
        &'a self,
        path: impl IntoIterator<Item = JsonNodePathSegment<'p>>,
        visit_value: impl FnMut(&'a T),
    ) -> Result<(), ()> {
        let mut path = path.into_iter();
        match path.next() {
            Some(JsonNodePathSegment::Key(key)) => {
                let Some(next) = self.0.get(key) else {
                    return Err(());
                };
                next.traverse_path(path, visit_value)
            }
            None => Ok(()),
            _ => Err(()),
        }
    }
}

impl<T> PathMapArray<T> {
    pub(crate) fn insert_element(&mut self, index: Index, child: PathMap<T>) -> &mut PathMap<T> {
        match self.0.entry(index) {
            Entry::Occupied(_) => panic!(
                "implementation error: PathTableArray::enter called with duplicate index {}",
                index
            ),
            Entry::Vacant(entry) => entry.insert(child),
        }
    }

    pub(crate) fn finish_subtree(self) -> PathMap<T> {
        PathMap {
            value: None,
            children: Children::Array(self),
        }
    }

    pub(crate) fn traverse_path<'a, 'p>(
        &'a self,
        mut path: impl Iterator<Item = JsonNodePathSegment<'p>>,
        visit_value: impl FnMut(&'a T),
    ) -> Result<(), ()> {
        match path.next() {
            Some(JsonNodePathSegment::Index(index)) => {
                let Some(next) = self.0.get(&index) else {
                    return Err(());
                };
                next.traverse_path(path, visit_value)
            }
            None => Ok(()),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::ops::Not;

    use super::*;
    use crate::JsonNodePath;

    #[test]
    fn path_map() {
        assert!(PathMap::<()>::default().is_empty_leaf());

        let mut root = PathMapObject::default();

        {
            let mut foo = PathMapObject::default();

            let foo_bar = foo
                .insert_key("bar".to_owned(), Default::default())
                .unwrap();
            assert!(foo_bar.is_empty_leaf());

            foo.insert_key("bar".to_owned(), Default::default())
                .unwrap_err();

            let foo_baz = foo
                .insert_key("baz".to_owned(), Default::default())
                .unwrap();
            assert!(foo_baz.is_empty_leaf());
            foo_baz.insert_value(2);
            assert!(foo_baz.is_empty_leaf().not());

            let mut foo = foo.finish_subtree();
            assert!(foo.is_empty_leaf().not());
            foo.insert_value(1);
            assert!(foo.is_empty_leaf().not());
            root.insert_key("foo".to_owned(), foo).unwrap();
        }

        {
            let mut pls = PathMapArray::default();

            let pls_0 = pls.insert_element(0, Default::default());
            assert!(pls_0.is_empty_leaf());

            let pls_42 = pls.insert_element(42, Default::default());
            assert!(pls_42.is_empty_leaf());
            pls_42.insert_value(3);
            assert!(pls_42.is_empty_leaf().not());

            let pls = pls.finish_subtree();
            assert!(pls.is_empty_leaf().not());
            root.insert_key("pls".to_owned(), pls).unwrap();
        }

        let collect = |path: &JsonNodePath| {
            let mut values = vec![];
            root.traverse_path(path.iter().copied(), |value| values.push(*value))
                .map(|_| values)
        };

        assert_eq!(collect(&[]), Ok(vec![]));
        assert_eq!(collect(&["foo".into()]), Ok(vec![1]));
        assert_eq!(collect(&["foo".into(), "bar".into()]), Ok(vec![1]));
        assert_eq!(collect(&["foo".into(), "baz".into()]), Ok(vec![1, 2]));
        assert_eq!(collect(&["pls".into()]), Ok(vec![]));
        assert_eq!(collect(&["pls".into(), 0.into()]), Ok(vec![]));
        assert_eq!(collect(&["pls".into(), 42.into()]), Ok(vec![3]));

        collect(&["quux".into()]).unwrap_err();
        collect(&[7.into()]).unwrap_err();
        collect(&["foo".into(), "quux".into()]).unwrap_err();
        collect(&["foo".into(), 7.into()]).unwrap_err();
        collect(&["pls".into(), "quux".into()]).unwrap_err();
        collect(&["pls".into(), 7.into()]).unwrap_err();
    }
}
