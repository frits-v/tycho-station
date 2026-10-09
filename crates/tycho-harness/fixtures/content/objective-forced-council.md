Choose how `widget` should report a lookup that found no match: `find_tag`
returns an empty collection, `find_label` returns a dedicated `NotFound`
variant. `has_tag` and `has_label` each call one shape, with equal standing.
