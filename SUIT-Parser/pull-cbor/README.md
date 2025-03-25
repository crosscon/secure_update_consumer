# pull-cbor

This is a CBOR library optimised for very constrained devices:
* it allocates no memory.
* it compiles to under 512 bytes.
* it includes (type only) schema validation.

This parser does not extract to Document Object Model. Instead, it has three possible operations for each CBOR element it encounters:

1. recurse into a container object and continue parsing
2. invoke a handler function
3. store a reference to the object at a specified pointer

The "schema" used by the parser is 8 bytes per element, which is substantially less than the code required to validate the types in a CBOR DOM or without a schema.
