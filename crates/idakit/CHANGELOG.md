# Changelog

## [0.1.1](https://github.com/Xevion/idakit/compare/idakit-v0.1.0...idakit-v0.1.1) (2026-07-12)


### Code Refactoring

* **sys:** Always compile probe bridges, drop test-shims feature and alias dep ([c618a40](https://github.com/Xevion/idakit/commit/c618a40de18dc1b6ebc3083ad260d6bf79ecf056))


### Documentation

* Generate README from idakit's crate doc via cargo-rdme ([c440f86](https://github.com/Xevion/idakit/commit/c440f8687534cc7abf26a52a07301e3622bd5e71))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * idakit-sys bumped from 0.1.0 to 0.1.1

## 0.1.0 (2026-07-11)


### Features

* **attrs:** Add func size/flags and segment perm/bitness/class with integration tests ([8c565f8](https://github.com/Xevion/idakit/commit/8c565f8bd34297fd1e57f52d5313f8efc5f11d64))
* **bytes:** Add patch and comment read with integration tests ([34e983f](https://github.com/Xevion/idakit/commit/34e983f62c911d3e5f53fe5d2c27823daf43a8be))
* **cfg:** Add control-flow graph with block arena, edges, and ranged instruction walk ([18ec9a7](https://github.com/Xevion/idakit/commit/18ec9a7481a8e374277ec969374bb45b99d5f458))
* **ci:** Move from Docker container to S3 runtime bundles with multi-OS matrix ([4c039e2](https://github.com/Xevion/idakit/commit/4c039e28e6a329fb89774be3d256c55ad00a61e8))
* **core:** Add main-thread kernel executor ([aea80f2](https://github.com/Xevion/idakit/commit/aea80f292a43ac6681ce8ee979c4cca40ba53590))
* **core:** Introduce safe idiomatic API layer with Ea, Func, Segment, and error types ([5cf7e28](https://github.com/Xevion/idakit/commit/5cf7e28a5d2ef592ba184f81d5206fd1c92f609f))
* **ctree:** Add Arena&lt;T&gt;/Idx&lt;T&gt; primitives and expose ctree module publicly ([d0a3abf](https://github.com/Xevion/idakit/commit/d0a3abf8b7093352b06f6ba5a0ff7c7a0f3dcb32))
* **ctree:** Add Cexpr/NodeRef accessors, expr_descendants, strip_casts, and Idb::ctree shorthand ([91cf5c2](https://github.com/Xevion/idakit/commit/91cf5c2b2c85020b8d51b0c164776a3a58164882))
* **ctree:** Add grouped operator enums mapped from ctype_t ([0a7be7b](https://github.com/Xevion/idakit/commit/0a7be7b5c038e4129650d20378eb5b49f1abc822))
* **ctree:** Add interned TypeTable and TypeKind variants for structured types ([ae0ca70](https://github.com/Xevion/idakit/commit/ae0ca706a800c4f9db51e0563f89a690a3216db0))
* **ctree:** Add node enums and the navigable Ctree ([17936f5](https://github.com/Xevion/idakit/commit/17936f52e59ea1d3210db73df48d6dcfe56d592a))
* **ctree:** Add structural query module for vtable installs and this-arg calls ([cb524f8](https://github.com/Xevion/idakit/commit/cb524f8934eb9be6de74705f4a4774c906d37c71))
* **ctree:** Implement flat ctree extraction from IDA facade to owned Ctree ([99bbf07](https://github.com/Xevion/idakit/commit/99bbf07150d8222ddd50f7b09fbadd0c17da2c68))
* **ctree:** Model the full argloc space for local variable locations ([7038478](https://github.com/Xevion/idakit/commit/703847834e0a9278ec82678c2e62397a1dd7962e))
* **ctree:** Propagate interned types through ExprNode and CtreeBuilder ([410f285](https://github.com/Xevion/idakit/commit/410f285beb2be1df2f550a7a0c84b324d0816065))
* **ctree:** Render owned Ctree back to C-like pseudocode for fidelity checks ([8996dc2](https://github.com/Xevion/idakit/commit/8996dc2205d25cb7cedeefdfe05adf58a3c5f6ac))
* **ctree:** Thread base_var through scaled pointer arithmetic for stripped binaries ([9d4be91](https://github.com/Xevion/idakit/commit/9d4be910ae5625fd34559e09667333329227879c))
* **data:** Expose fixed-width, pointer, and C-string reads over the database ([15c022e](https://github.com/Xevion/idakit/commit/15c022eeb4114f83e96dd40ee6538aeeb3abec2f))
* **decode:** Lift register naming onto the types and fan decode across the corpus ([c860cc1](https://github.com/Xevion/idakit/commit/c860cc1bf8d008f7f4026b89ebab8a1f1ff8e321))
* **decode:** Name st/cr/dr/tr registers faithfully ([1090e1d](https://github.com/Xevion/idakit/commit/1090e1d179b46363b9cd910bee6694a20e243758))
* **decode:** Strict operand decode with a Bnd class and typed errors ([4d873a5](https://github.com/Xevion/idakit/commit/4d873a5c40bc7b1ea8c8cbcd8364f963f5de6402))
* **expr:** From-scratch function-prototype builder ([0165833](https://github.com/Xevion/idakit/commit/0165833df52a97e52d31a87ac76eb16d0d9b830f))
* **expr:** Let FunctionExpr set a calling convention ([a183fc4](https://github.com/Xevion/idakit/commit/a183fc4277933ea748a5ff76b0537b1a0067a07f))
* **expr:** TypeExpr builder with tinfo_t lowering ([d089e3a](https://github.com/Xevion/idakit/commit/d089e3ab1c0022f1c12f6864298a964b3a9f2567))
* **facade:** Surface loader-rejection reasons via msg()-channel capture ([9a0dd5f](https://github.com/Xevion/idakit/commit/9a0dd5f1aad524c53199169722bdaf0e488b7f81))
* **frame:** Expose function stack frames as owned Frame snapshots with FrameVar/FrameVarKind ([e8115fb](https://github.com/Xevion/idakit/commit/e8115fbc0f834e9a0b0fd14fcdceed33e7031cd8))
* **func:** Add Send FuncImage snapshot to carry function facts off the kernel thread ([f9b2ab8](https://github.com/Xevion/idakit/commit/f9b2ab8f665874e57f0ba5ec856b09bf6031d7a7))
* **function:** Prototype surgery verbs ([c3a9847](https://github.com/Xevion/idakit/commit/c3a984727eec245c97357614f12739fe818451fc))
* **gen:** Fold the bytes domain ([157e960](https://github.com/Xevion/idakit/commit/157e960e2e64f3a7e3b03a507a88816ee3bb4186))
* **gen:** Fold the cfg and reference domains ([6df6991](https://github.com/Xevion/idakit/commit/6df6991b6dfee9baddcd78428ecba8896f93a518))
* **gen:** Fold the function domain into the generated bridge ([b6ad2c1](https://github.com/Xevion/idakit/commit/b6ad2c1818a3147163b1d227340be6cdaa308cba))
* **gen:** Fold the meta, export, name, and strings domains ([7c393b6](https://github.com/Xevion/idakit/commit/7c393b66d54bbcabb28072a25469d3e2ad7cb408))
* **hexrays:** Decompile through the generated cxx handle ([db79d3e](https://github.com/Xevion/idakit/commit/db79d3ecf142810487f3731d6da54c7570942fe6))
* **idakit:** Add Ida::here for direct on-thread kernel access ([2da1b98](https://github.com/Xevion/idakit/commit/2da1b98567dbd78bdfc790a3e71f9fd92680267b))
* **idakit:** Convert open to a builder and support headless auto-analysis ([d96919f](https://github.com/Xevion/idakit/commit/d96919f5be4097d3f0c301bd4cce26606afb008b))
* **idakit:** Implement Hash, Ord, Display, and Sub for core types ([3b9f288](https://github.com/Xevion/idakit/commit/3b9f288fdbdf862629ee3ae069715f6346602845))
* **idakit:** Trap IDA fatal exits and add CI infrastructure for integration tests ([3ec7fb6](https://github.com/Xevion/idakit/commit/3ec7fb66e7198bc9bd3d8eaada8b2f47827fe881))
* **idb:** Database metadata snapshot and name lookup ([d4ade4d](https://github.com/Xevion/idakit/commit/d4ade4db83473f67345f9bcd43602985f4783fca))
* **imports:** Add import/export enumeration via facade snapshot and typed iterators ([4be4a96](https://github.com/Xevion/idakit/commit/4be4a96303607de0d4b05d37380376bb0a8eeff6))
* **insn:** Code-gated Func::instructions() over all chunks ([af46090](https://github.com/Xevion/idakit/commit/af4609041dc50edc4fb89d1a0bc2b3948e4c62a8))
* **insn:** Decode through the generated cxx bridge ([4f864a6](https://github.com/Xevion/idakit/commit/4f864a68d01a7275a42713f4461a4a503499a36d))
* **insn:** Implement Idb::decode with mnemonic, operands, and control-flow facts for x86/x64 ([b88f421](https://github.com/Xevion/idakit/commit/b88f42132979011b9a82040857993bf22edd4538))
* **kernel:** Expose batch flag on IdaConfig, default on for headless bring-up ([cdff5af](https://github.com/Xevion/idakit/commit/cdff5af2f63ee16ae5d75a26fb0c8ebc86038c6d))
* **members:** Durable MemberRef with staleness detection ([135425d](https://github.com/Xevion/idakit/commit/135425dc3532b9c9ba9dc78e45332b04ae9657a7))
* **members:** Enum-constant edits ([a92b738](https://github.com/Xevion/idakit/commit/a92b738d9caba134939eee3085562cd09db05dc8))
* **members:** Struct and union member edits ([8331141](https://github.com/Xevion/idakit/commit/833114129921d38ccd0ae2e0b94fc8184a0df8b8))
* **name:** Return FunctionName sum type from Function::name() ([772089b](https://github.com/Xevion/idakit/commit/772089b4572eb6fc80f9ff1601629381ff02c027))
* **runtime:** Cover interr throw path in guarded&lt;&gt;, force TVHEADLESS on kernel bring-up ([2df2b90](https://github.com/Xevion/idakit/commit/2df2b90681ccc6b9fcba584f84643043486f6735))
* **runtime:** Extend fatal traps to abort(), add trap and fault-injection test suites ([71fdafd](https://github.com/Xevion/idakit/commit/71fdafd53147dfa41d3ad9ac4e32afb26725b85f))
* **search:** Add binary pattern search with Pattern and Matches iterator ([c9f039f](https://github.com/Xevion/idakit/commit/c9f039fa11ce6640154adb4e236479b086e7c9c8))
* **segment:** Typed SegmentClass classification ([edba1c7](https://github.com/Xevion/idakit/commit/edba1c7a1b4ec8819133bb065570f5c952eb2f8d))
* **strings:** Add Strings iterator and StringLiteral view over IDA's strlist ([c4bd094](https://github.com/Xevion/idakit/commit/c4bd0945b11581dd791b02131a5c893b7f9c9ba5))
* **tests:** Source the dedicated tests from the corpus canonical fixture ([f9cf17f](https://github.com/Xevion/idakit/commit/f9cf17f5d70f9c3f6cdc88f3d0c2fa05583bc12d))
* **ty:** Add TypeInfo, a node-at-a-time type builder ([aeea4c7](https://github.com/Xevion/idakit/commit/aeea4c7527aacbb1f5bc7dd5d20ebdd0b8ea8cb6))
* **ty:** Drive type walks through the cxx visitor ([9cc27f7](https://github.com/Xevion/idakit/commit/9cc27f75e52fa48b4efd8b8bf6cc50b0b1e05eaa))
* **types:** Add Opaque variant for named-but-bodyless types and handle bitfields ([b423b15](https://github.com/Xevion/idakit/commit/b423b151dd9b509f1d81c5a32ba5987c5829085d))
* **types:** Cross-database type diff via CanonicalType, TypeCatalog, and ordinal enumeration ([501939a](https://github.com/Xevion/idakit/commit/501939af515e96f8e094fa35a04ac4f40cacac93))
* **types:** Extract shared type walker and add structured frame type walk ([02e0e49](https://github.com/Xevion/idakit/commit/02e0e49a44ca04a0b65bf4e111b3a869d59ab0c4))
* **write:** Clear_type on location and function cursors ([a3dc95f](https://github.com/Xevion/idakit/commit/a3dc95f5b100a62bc9dcfca707a416f6ece5f3d2))
* **write:** Cursors, type-apply, and define ([93b68a4](https://github.com/Xevion/idakit/commit/93b68a45b7bdf516b7d6122526091c3ae2fd7b62))
* **xref:** Lazy xref cursor with xrefs_to/xrefs_from on Idb and Func ([617fd66](https://github.com/Xevion/idakit/commit/617fd66ef555d7222f7aa08e91659002f36722d3))
* **xref:** Surface reference origin (user vs IDA analysis) ([0ff9cbf](https://github.com/Xevion/idakit/commit/0ff9cbfe7f1f8ca3bf6fb9ba39c94b6e05a62b94))


### Bug Fixes

* **corpus:** Return exit code from main so the banner swallow runs on Windows ([ea81f72](https://github.com/Xevion/idakit/commit/ea81f72de9b8c4fcd8629e8dfb48c7f653a0b72c))
* **ctree:** Assert decompile extraction against visitor-minus-elided-empties ([3e943e0](https://github.com/Xevion/idakit/commit/3e943e06cb625d1bd42cfbe8e445a2e6c6b9c412))
* **ctree:** Assign size to typedef nodes from their underlying type ([541d134](https://github.com/Xevion/idakit/commit/541d13400f6ed7d415ff42a3024ec0d1c86a64d6))
* **ctree:** Handle empty member names by resolving the subobject's aggregate type ([784d1cf](https://github.com/Xevion/idakit/commit/784d1cf18f19f357b5ac73063cec2395abc019df))
* **docs:** Escape example doc-comment placeholders, lint them in `just check` ([cfad3d3](https://github.com/Xevion/idakit/commit/cfad3d3216baac9e3ce8a555eadc2f21f737054c))
* **ea:** Order Ea by address, not by the inverted niche ([2b43983](https://github.com/Xevion/idakit/commit/2b43983e3629a7cf05738378f3894478933ac64d))
* **idakit-sys:** Avoid passing BADSIZE sentinel as scalar byte width in facade ([bdb97f5](https://github.com/Xevion/idakit/commit/bdb97f54ea43a929c6d7c5e284cd8aba20bd5831))
* **idakit-sys:** Catch C++ exceptions in all facade entry points and abort ([102cde2](https://github.com/Xevion/idakit/commit/102cde23f33ebce402a3f159383c2b5d696849c3))
* **idakit:** Split `Members` lifetime params to avoid over-constraining callers ([dfc5e1b](https://github.com/Xevion/idakit/commit/dfc5e1b560cf2140eb0bebf01a46152ca10a2365))
* **members:** Stale a MemberRef when a deleted member leaves a gap ([b3cfe15](https://github.com/Xevion/idakit/commit/b3cfe15526a328a1c751b3d53b7a6f68a8bb98d1))
* **test:** Add common test_db helper with IDADIR fallback, swallow IDA exit banner ([b8c3610](https://github.com/Xevion/idakit/commit/b8c361081490940dba627bcd3172a052aa84b486))
* **test:** Isolate integration tests via per-test db copies to avoid IDA exclusive-lock conflicts ([60e4e56](https://github.com/Xevion/idakit/commit/60e4e56893686d14c6f483af0bce0e1191ecc410))
* **ty:** Harden type construction against bad input ([cb3f51d](https://github.com/Xevion/idakit/commit/cb3f51d1b195649f7f5592591b48a62ff09239fd))


### Performance Improvements

* **corpus:** Amortize open across checks by collapsing per-check trials into per-db trials ([a2ad467](https://github.com/Xevion/idakit/commit/a2ad4678f4698d68013525de8d19ef07b5beb6b4))


### Code Refactoring

* **address:** Remove Offset in favor of u64 Add and distance_to span ([f391fee](https://github.com/Xevion/idakit/commit/f391feea921f9ad6317ada82d5b268b8a4ab6bff))
* **api:** Replace Ea/func/insn/xref abbreviations with unambiguous full names ([e3ca795](https://github.com/Xevion/idakit/commit/e3ca79592606d5121591fc03d0267673df18ef11))
* **bitness:** Replace raw bitness u8 with typed Bitness enum on meta and segment ([b3ed354](https://github.com/Xevion/idakit/commit/b3ed3547410acac7eb98d21847a92eb825cf7276))
* **build:** Replace Linux-hardcoded paths and ifdefs with per-OS platform constants ([ebec425](https://github.com/Xevion/idakit/commit/ebec425adf2724492ae3f2e72d5e156ccc91dc92))
* **cfg:** Reject unmodeled block kinds instead of an Unknown catch-all ([229e569](https://github.com/Xevion/idakit/commit/229e569198aee3f8df2777fb19527c85924dfa37))
* **conv:** Use std conversion traits over hand-written raw wrappers ([eda85d4](https://github.com/Xevion/idakit/commit/eda85d489abd54c98b9c02a6e67cce94d89a3941))
* **core:** Decouple kernel from OS main thread and centralise FFI ([066b114](https://github.com/Xevion/idakit/commit/066b11419f6b3e05c7c135ac8ff2ba4218762e32))
* **core:** Enforce thread affinity with !Send Idb ([842c931](https://github.com/Xevion/idakit/commit/842c93139297dcabbf06dfa1a04d6ea7af928e4a))
* **core:** Replace panics with structured error types across kernel boundary ([d78bcc9](https://github.com/Xevion/idakit/commit/d78bcc95a5f24b1c9a2413f2e97038284295bd7e))
* **corpus:** Promote corpus module to crate-level, deduplicate doctest harness ([3927f07](https://github.com/Xevion/idakit/commit/3927f07a53df11fc7fab07972c1d20f5ffc30e71))
* **ctree:** Add builder shorthand methods and flatten tree accessors ([4c7ed32](https://github.com/Xevion/idakit/commit/4c7ed327a1f087ed79749d971a6cc009186613a7))
* **ctree:** Add TypeKind::pointee accessor and simplify pointee_size ([5935299](https://github.com/Xevion/idakit/commit/593529928fb32729549dd96af7310c6992c726cd))
* **ctree:** Drop op raw wrappers and non_exhaustive on closed node/type enums ([b0393b3](https://github.com/Xevion/idakit/commit/b0393b32f4eff4475afcff730c829e03658be4fa))
* **ctree:** Expose ExactSizeIterator accessors for whole-tree scans ([0fa6bcd](https://github.com/Xevion/idakit/commit/0fa6bcd505814e709c3c32b60c049a40a687b699))
* **ctree:** Keep query primitives public, move C++ matcher impls into ctor test ([c69bca1](https://github.com/Xevion/idakit/commit/c69bca170ba1b14d8a8b3678f1833e1954f415cc))
* **ctree:** Promote operator glyphs and this_lvar from free fns to methods ([03378c9](https://github.com/Xevion/idakit/commit/03378c90cd15cfe344f95a85e07c1c3ccdbcc49d))
* **ctree:** Rename offset to byte_offset, add tracing, and improve docs ([8eb2c1d](https://github.com/Xevion/idakit/commit/8eb2c1dfa7e34d4ff544d9dbf4233541f0f01f6f))
* **ctree:** Replace flat record extraction with streaming vtable walk ([555de77](https://github.com/Xevion/idakit/commit/555de77e3e0facdd52c87b324736ae6d5502fafa))
* Drop non_exhaustive on closed enums ([6a61d70](https://github.com/Xevion/idakit/commit/6a61d70c2d5bbfdba264cd880cd582b2f20c8c79))
* **error:** Unify the type-write error surface into TypeWriteError ([ee9c979](https://github.com/Xevion/idakit/commit/ee9c979f1bf748abe7f7c00954621019cda405b2))
* **facade:** Fold the two named-type load helpers into one ([200246b](https://github.com/Xevion/idakit/commit/200246b8cdff6096174add704071cf1e4f8e70d2))
* **function:** Split instruction iterators and signature domain out ([32b8cc9](https://github.com/Xevion/idakit/commit/32b8cc958f35c7ea35c27d7731e02faf48221d4c))
* **idakit:** Expose domains as modules with a prelude; contain idalib bleed ([33d6911](https://github.com/Xevion/idakit/commit/33d6911f83e269ec1978eec2d2f50c9d547b9a71))
* **idakit:** Flip the read path onto the generated bridge ([0c43ae9](https://github.com/Xevion/idakit/commit/0c43ae9d1f8c69071386bfa24d91df5c35231e4b))
* **idakit:** Rename public API to human/domain vocabulary ([21c6a40](https://github.com/Xevion/idakit/commit/21c6a4050b517dfda0c6a5a1b69785040712f1d4))
* **idakit:** Reorganize modules into task-shaped pillars ([e8c93c5](https://github.com/Xevion/idakit/commit/e8c93c5b73e7490685157ffdaeb4413a70278640))
* **idb:** Move Idb impls to domain modules, extract Ida kernel host ([826ca12](https://github.com/Xevion/idakit/commit/826ca12f39e25717dd42196769ca53536bc49beb))
* **kernel:** Expose IdaConfig builder via Ida::new(), keep run/here as zero-config shortcuts ([0c7dc43](https://github.com/Xevion/idakit/commit/0c7dc4374be0e6c11be7bad3eaffccbe4d3cb4cb))
* **search:** Expand Pattern API with named constructors and structured PatternRejection ([e25a661](https://github.com/Xevion/idakit/commit/e25a6619ccae00fa9371c457f9e4fd6860b7c30c))
* **sys:** Delete the raw facade ([943ecd8](https://github.com/Xevion/idakit/commit/943ecd8bb976c7326370d3affe2b8946be5e92bc))
* **sys:** Strip the cfunc spike to its inline path ([b7ea7fc](https://github.com/Xevion/idakit/commit/b7ea7fcf70b8548ab6491f8737f00ccedf8094a0))
* **test:** Convert harness=false tests to #[test] via Ida::run, serialize with nextest ([3dd30ba](https://github.com/Xevion/idakit/commit/3dd30ba965673e93d2002ac5cebc3969e8dc0a58))
* **tests:** Fold per-test kernel setup into with_canonical_db ([9b031f9](https://github.com/Xevion/idakit/commit/9b031f912c2d3b9aad9be67cde4b0058bbd52e45))
* **tests:** Migrate assertions to assert2 and parameterize with rstest ([be49596](https://github.com/Xevion/idakit/commit/be49596243d8508eeec97cabc37205d7772afcda))
* **ty:** Flip the write side onto the generated bridge ([ab8cc93](https://github.com/Xevion/idakit/commit/ab8cc93e8fcc67389117d7372c713f6f426c0d02))
* **types:** Replace kernel-bound TypeInfo with Send TypeImage backed by interned TypeTable ([74202e2](https://github.com/Xevion/idakit/commit/74202e2701637ff598b1eca3f0e501bc9d361b65))
* **types:** Separate TypeBuilder construction from TypeTable and move types to crate root ([e147eab](https://github.com/Xevion/idakit/commit/e147eab5c3a6e85795f06b163d994444062194fc))
* **xref:** Complete the cref_t/dref_t mirror and reject unmapped types ([22aee81](https://github.com/Xevion/idakit/commit/22aee818a8b85968aed7ca09ec32341c10baff38))
* **xref:** Make Xrefs genuinely lazy ([b226392](https://github.com/Xevion/idakit/commit/b226392d0d55c168bb8117b401f01f88d2bff129))


### Documentation

* **ctree:** Add doc-tests for Ctree and base_var using CtreeBuilder ([9c521d0](https://github.com/Xevion/idakit/commit/9c521d001b918ff12edf9f0d03d4df939fbd4dfd))
* **ctree:** Cover all public node and error fields to satisfy deny(missing_docs) ([b325eaa](https://github.com/Xevion/idakit/commit/b325eaaa25e2e4dbe9b00987c7e7a8f838402888))
* **idakit:** Add logo, favicon, and README banner ([a01fc2d](https://github.com/Xevion/idakit/commit/a01fc2d365b01463a725b0dd0c8fcca1c87fb241))
* **idakit:** Add TODO stubs for missing attributes, instruction layer, and DB metadata ([6e7c75d](https://github.com/Xevion/idakit/commit/6e7c75de39f12600fef82e83cb24eba694ebec0b))
* **idakit:** Reflow and restructure doc comments crate-wide ([c78281a](https://github.com/Xevion/idakit/commit/c78281a5324484f57d66bc504862abb112ca2dff))
* **idakit:** Rewrite crate front page and README ([ba8ce1f](https://github.com/Xevion/idakit/commit/ba8ce1f564222254995c2615d3a292a566693ff6))
* **idakit:** Standardize type-summary openers by category ([1a10c21](https://github.com/Xevion/idakit/commit/1a10c21a3e9319e6cec3491f06674c92feee9c99))
* **idakit:** Tighten and reflow doc prose across ctree, types, and core modules ([806ba23](https://github.com/Xevion/idakit/commit/806ba238eb8492a1a4b2c1656e1e8b665d239d68))
* **import:** Correct the name/ordinal exclusivity claim ([6adbeb7](https://github.com/Xevion/idakit/commit/6adbeb7d342ab2b708bc363d9196b6a0442bccf7))
* Make crates publishable — metadata, deny(missing_docs), README, docs.rs ([3bf7b4b](https://github.com/Xevion/idakit/commit/3bf7b4bc9ecea300c0ca9cbf27754ab2ef39ea98))
* Tidy comments across the cxx overhaul ([ac05ec2](https://github.com/Xevion/idakit/commit/ac05ec2dc2b94f4633663b1e87eb26ce017f3dd2))
* **types:** Add runnable doctests and doctest harness module ([e0a9007](https://github.com/Xevion/idakit/commit/e0a90076cf15b7835d1dae0113300f8fb1902917))


### Continuous Integration

* **docs:** Enforce rustdoc lints via deny attributes, just doc recipe, and CI step ([50ff9d9](https://github.com/Xevion/idakit/commit/50ff9d92334c6c945d96921581a21e45e999842c))
* **release:** Wire release-please and crates.io publish pipeline ([cd00924](https://github.com/Xevion/idakit/commit/cd0092473eec960c4fb3f5814271153fb5bef09d))


### Miscellaneous

* **cxx:** Restore the cxx-interop spike as the overhaul baseline ([50f2f77](https://github.com/Xevion/idakit/commit/50f2f7743fd8419122edcc1ac0f38d5c7f299aba))
* **types:** Retire type/frame string APIs, add tag_name accessor ([7b1f73f](https://github.com/Xevion/idakit/commit/7b1f73f03c0ac2be39f37a8c9e8fb9b9989f89ec))
