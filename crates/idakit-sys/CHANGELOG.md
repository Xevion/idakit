# Changelog

## [0.1.2](https://github.com/Xevion/idakit/compare/idakit-sys-v0.1.1...idakit-sys-v0.1.2) (2026-07-18)


### Features

* **accessors:** Expand read accessors across function, segment, name, xref, and instruction ([0c0c93b](https://github.com/Xevion/idakit/commit/0c0c93bf001dc107a0496d6114aa36113f7df051))
* **decompiler:** Add cache invalidation API, auto-invalidate FunctionEdit writes ([8ddd4ae](https://github.com/Xevion/idakit/commit/8ddd4aedfe4e86be3140e6f59593533e631ac790))
* **enum:** Add is_bitmask to TypeShape::Enum, set_bitmask/add_flag to TypeEdit ([ce3b1d0](https://github.com/Xevion/idakit/commit/ce3b1d067cec602a93d9bce25340ee8771d218cf))
* **instruction:** Surface EVEX masking, broadcast, and FP control ([b2da07d](https://github.com/Xevion/idakit/commit/b2da07d135ee0caaebe7388a9133e067d6f86610))
* **location:** Push cache invalidation into LocationMut, add refresh_text ([d480555](https://github.com/Xevion/idakit/commit/d4805559df670c5751458203d5732075e81d3c4b))
* **member:** Add set_udm_cmt via MemberEdit::comment, expr::bitfield leaf ([833d2a2](https://github.com/Xevion/idakit/commit/833d2a2101eebdfb47becb21d47844f017b08ecb))
* **netnode-facade:** Complete coverage with address-keyed, idx8, shift, and ranged-delete ops ([a4adbb0](https://github.com/Xevion/idakit/commit/a4adbb0cc3e9155325db02f202a0d56202d65862))
* **netnode-facade:** Emit SDK doc aliases on generated re-exports ([3587bb9](https://github.com/Xevion/idakit/commit/3587bb9a98aa4bcf5d4e0d370b99697cffa98a5a))
* **netnode-facade:** Generate netnode facade covering lifecycle, arrays, and blob ops ([36d7af6](https://github.com/Xevion/idakit/commit/36d7af6bdd37356cca195244f25dd2c5ce53167a))
* **netnode:** Add Netnode/NetnodeMut API with iterators, Persist trait, and raw bindings ([647e6fb](https://github.com/Xevion/idakit/commit/647e6fb403343ee75ce6fce1d19b680adcb28905))
* **netnode:** Add serde feature for typed hash and blob netnode storage ([5cd2521](https://github.com/Xevion/idakit/commit/5cd252152efcf461ce285e592ebbf9acf8f32696))
* **repr:** Add MemberRepr/NumberFormat, MemberEdit::set_repr for value_repr_t ([98f5ed8](https://github.com/Xevion/idakit/commit/98f5ed81f1cb4b27083f225dd8e2eba5ac1746ab))
* **repr:** Unify MemberRepr into ValueRepr, add TypeShape::Enum::repr, TypeEdit set_repr/width ([563b957](https://github.com/Xevion/idakit/commit/563b957e9494ac30c6a4cac183b251949aeee919))
* **types:** Expose forward-declare and enum-del-by-value through the write API ([9574886](https://github.com/Xevion/idakit/commit/9574886132d9328a3b484b117d3e1b97011409a5))
* **types:** Expose TypesMut::delete and TypesMut::rename for til types ([edd427d](https://github.com/Xevion/idakit/commit/edd427d6ea83699ef195df250d541fa7b7cdc656))
* **udm:** Pass etf_flag_t through set_udm_type, add_edm, and rename_edm ([12f6fa7](https://github.com/Xevion/idakit/commit/12f6fa705afb5253e5002c9dae284ef5d0efd4cf))


### Bug Fixes

* **facade:** Clamp truncated facade reads and bound type-write param count ([b25c53c](https://github.com/Xevion/idakit/commit/b25c53cf90daca6ecff31e024c7a488173972612))
* **facade:** Suppress false-positive va_copy analyzer warning ([6b58fd2](https://github.com/Xevion/idakit/commit/6b58fd2be78ccfae79f6ac78ea3f213de4a600ed))
* **idakit-sys:** Use case-insensitive .app extension check in build.rs ([a32ddb1](https://github.com/Xevion/idakit/commit/a32ddb1f381956daee385aab12342f91ac2b2c4d))
* **netnode:** Reject netnode values over MAXSPECSIZE and clamp truncated reads ([5825d63](https://github.com/Xevion/idakit/commit/5825d63a1f4f851e07a35854046faa24b2e9f793))
* **patch:** Guard patch_bytes wrap, drop stale HexRaysInit field, dedupe invalidation ([e80a5d2](https://github.com/Xevion/idakit/commit/e80a5d281cf5f5d6544336e079de359ee782b7d3))
* **tidy:** Emit absolute paths in compile_commands.json so ctcache caches ([d10beec](https://github.com/Xevion/idakit/commit/d10beec59903695fe54f16cf712e95577bdd6870))


### Code Refactoring

* **codegen:** Explode build_support spec into domains/ and visitors/ submodules ([5a9078a](https://github.com/Xevion/idakit/commit/5a9078af6d42acf30d3064c31eb8557fabc3e965))
* **codegen:** Fold ExternTy free helpers and visitor raw constructors into impl blocks ([ccb3f33](https://github.com/Xevion/idakit/commit/ccb3f33713da3ca92eafa0033f6da792d28e85e8))
* **codegen:** Generate bytes and ty domains, retire raw binpat/patch/type FFI ([9fa0b2d](https://github.com/Xevion/idakit/commit/9fa0b2decf471051e9ddaded66a53d02d28f0c7b))
* **codegen:** Hoist marshalling helpers into shared gen_helpers.h, drop body_helpers field ([3369817](https://github.com/Xevion/idakit/commit/33698175831993673ab2a5f2684277fd2da4baa5))
* **codegen:** Introduce args!/fields!/methods! DSL macros, collapse spec boilerplate ([2e4b22d](https://github.com/Xevion/idakit/commit/2e4b22da3c900c01cae4c0dea2e6a455fcd66c43))
* **codegen:** Purge idakit_ namespace prefix, rename archives and extern C symbols to match ([7be0b74](https://github.com/Xevion/idakit/commit/7be0b742533ff2f40df201409725ba7865371c16))
* **codegen:** Separate model, emit, and dsl concerns out of gen.rs ([2dd8388](https://github.com/Xevion/idakit/commit/2dd838869c7ac8a5fb880ac4c5cf9c1fe0ec52f8))
* **codegen:** Spec-drive integer sentinels via ConstDef, retire facade #defines ([f36d518](https://github.com/Xevion/idakit/commit/f36d5187520e5986828ddb7790089fa40f907837))
* **codegen:** Split codegen engine into its own workspace crate ([3fe80a9](https://github.com/Xevion/idakit/commit/3fe80a9d00c4b5526dcf3334872f315b7ff83dff))
* **ctree:** Migrate ctree walk from raw fn-pointer table to cxx bridge ([8beddcf](https://github.com/Xevion/idakit/commit/8beddcf073ebdc30f0d9f2260ef322b351ea27c0))
* **facade:** Apply static_cast/reinterpret_cast uniformly and rename locals for clarity ([6404c79](https://github.com/Xevion/idakit/commit/6404c793978777ed73063670e7fa1fca92379bb5))
* **facade:** Codegen NONE/EXIT_TRAPPED/FATAL_* into gen_facade_consts.h, strip IDAKIT_ prefix ([76b16b1](https://github.com/Xevion/idakit/commit/76b16b1be4a0ef31d259ecf9773a8050b7e36499))
* **facade:** Codegen visitor bridge, merge bridge_ctree/typewalk into bridge_visitors ([af89dd5](https://github.com/Xevion/idakit/commit/af89dd5b745f72925a7c86f0b020cd06950ee5c7))
* **facade:** Convert raw flag/result constants to typed bitflags and enums, add doc aliases ([ed8a06d](https://github.com/Xevion/idakit/commit/ed8a06d1ab60e561243068b05324a76b0ad18c96))
* **facade:** Decompose type_build.cpp into apply/define/udt/enum/sig/build TUs ([5260f3b](https://github.com/Xevion/idakit/commit/5260f3bc37df265085a34de4bc341cacd9dc3054))
* **facade:** Migrate &[u8]/&str args to owned String, add strlit_escaped ([e54afb4](https://github.com/Xevion/idakit/commit/e54afb44f446028104d6fa0b40aed94af4293cdd))
* **facade:** Rename gen_* facade TUs to *_custom, flag modules to *_flags, cfg2 to cfg_check ([33308c0](https://github.com/Xevion/idakit/commit/33308c0129e110bc15f02b6e5d597b6874665879))
* **facade:** Rename TUs to bare domain names, fold db.cpp into bytes.cpp, broaden tidy scope ([66bcbd1](https://github.com/Xevion/idakit/commit/66bcbd16841b826327168609825618377e419bc6))
* **facade:** Retire cfg_check/AddrCursor/WriteOutcome bridges, promote flags to typed bitflags ([5104e1e](https://github.com/Xevion/idakit/commit/5104e1eb6de5e9c1b884b11e97413310b7e657d0))
* **facade:** Split gen.rs engine from spec data, matrix-generate netnode ([2cee76d](https://github.com/Xevion/idakit/commit/2cee76def8dcea3fb4ad811a60235e70b63335cb))
* **facade:** Strip idakit_ prefix from all C facade symbols ([76527f8](https://github.com/Xevion/idakit/commit/76527f8fc7af80ff040a3c523ce67884962459a0))
* Rename SDK-flavoured public names to domain words ([a9969de](https://github.com/Xevion/idakit/commit/a9969def2b0f46590e789f0082a08f9d73eb1287))


### Documentation

* Drop self-referential "this page" wording from alias-search docs ([dff249c](https://github.com/Xevion/idakit/commit/dff249c5d3e0960c0d48aefab67c75b7fc4f9912))
* **facade:** Annotate all facade bodies and introduce README ([2f3619f](https://github.com/Xevion/idakit/commit/2f3619fa1f5b123a4a0149b58c7aa2b818b17dc3))
* **idakit-sys:** Add README and expand crate-level doc, wire into readme recipe ([3a812d1](https://github.com/Xevion/idakit/commit/3a812d15a9af20e9567abfe25912e34dbb3ae57c))


### Miscellaneous

* **lint:** Rollout workspace-level lints, Self pattern adoption, and FFI doc coverage ([6afc283](https://github.com/Xevion/idakit/commit/6afc28328bdb60a220166f0e56ba1700ae74640d))

## [0.1.1](https://github.com/Xevion/idakit/compare/idakit-sys-v0.1.0...idakit-sys-v0.1.1) (2026-07-12)


### Bug Fixes

* **release:** Alias idakit-sys self dev-dep to avoid release-please cycle ([7d86335](https://github.com/Xevion/idakit/commit/7d86335e1172b222003bc26f63cb3721d964d886))


### Code Refactoring

* **sys:** Always compile probe bridges, drop test-shims feature and alias dep ([c618a40](https://github.com/Xevion/idakit/commit/c618a40de18dc1b6ebc3083ad260d6bf79ecf056))

## 0.1.0 (2026-07-11)


### Features

* **attrs:** Add func size/flags and segment perm/bitness/class with integration tests ([8c565f8](https://github.com/Xevion/idakit/commit/8c565f8bd34297fd1e57f52d5313f8efc5f11d64))
* **bytes:** Add patch and comment read with integration tests ([34e983f](https://github.com/Xevion/idakit/commit/34e983f62c911d3e5f53fe5d2c27823daf43a8be))
* **cfg:** Add control-flow graph with block arena, edges, and ranged instruction walk ([18ec9a7](https://github.com/Xevion/idakit/commit/18ec9a7481a8e374277ec969374bb45b99d5f458))
* **ci:** Move from Docker container to S3 runtime bundles with multi-OS matrix ([4c039e2](https://github.com/Xevion/idakit/commit/4c039e28e6a329fb89774be3d256c55ad00a61e8))
* **core:** Introduce safe idiomatic API layer with Ea, Func, Segment, and error types ([5cf7e28](https://github.com/Xevion/idakit/commit/5cf7e28a5d2ef592ba184f81d5206fd1c92f609f))
* **ctree:** Add Cexpr/NodeRef accessors, expr_descendants, strip_casts, and Idb::ctree shorthand ([91cf5c2](https://github.com/Xevion/idakit/commit/91cf5c2b2c85020b8d51b0c164776a3a58164882))
* **ctree:** Implement flat ctree extraction from IDA facade to owned Ctree ([99bbf07](https://github.com/Xevion/idakit/commit/99bbf07150d8222ddd50f7b09fbadd0c17da2c68))
* **ctree:** Model the full argloc space for local variable locations ([7038478](https://github.com/Xevion/idakit/commit/703847834e0a9278ec82678c2e62397a1dd7962e))
* **data:** Expose fixed-width, pointer, and C-string reads over the database ([15c022e](https://github.com/Xevion/idakit/commit/15c022eeb4114f83e96dd40ee6538aeeb3abec2f))
* **decode:** Name st/cr/dr/tr registers faithfully ([1090e1d](https://github.com/Xevion/idakit/commit/1090e1d179b46363b9cd910bee6694a20e243758))
* **decode:** Strict operand decode with a Bnd class and typed errors ([4d873a5](https://github.com/Xevion/idakit/commit/4d873a5c40bc7b1ea8c8cbcd8364f963f5de6402))
* **expr:** From-scratch function-prototype builder ([0165833](https://github.com/Xevion/idakit/commit/0165833df52a97e52d31a87ac76eb16d0d9b830f))
* **expr:** TypeExpr builder with tinfo_t lowering ([d089e3a](https://github.com/Xevion/idakit/commit/d089e3ab1c0022f1c12f6864298a964b3a9f2567))
* **facade:** Bridge hex-rays decompilation ([a04b430](https://github.com/Xevion/idakit/commit/a04b430d093e6f6d1c50e5669af3077d977d42b9))
* **facade:** Enumerate functions and segments ([82da490](https://github.com/Xevion/idakit/commit/82da4904ff26edbadf2df5a0d61728698b7d22bc))
* **facade:** Expose type info and struct layout ([2798145](https://github.com/Xevion/idakit/commit/2798145b9eae2b00d02b6fd329ab9bd6664595d3))
* **facade:** Read bytes and cross-references ([d515b16](https://github.com/Xevion/idakit/commit/d515b16392af9db55c322532f279cfc59e21f572))
* **facade:** Surface loader-rejection reasons via msg()-channel capture ([9a0dd5f](https://github.com/Xevion/idakit/commit/9a0dd5f1aad524c53199169722bdaf0e488b7f81))
* **frame:** Expose function stack frames as owned Frame snapshots with FrameVar/FrameVarKind ([e8115fb](https://github.com/Xevion/idakit/commit/e8115fbc0f834e9a0b0fd14fcdceed33e7031cd8))
* **function:** Prototype surgery verbs ([c3a9847](https://github.com/Xevion/idakit/commit/c3a984727eec245c97357614f12739fe818451fc))
* **gen:** Fold the bytes domain ([157e960](https://github.com/Xevion/idakit/commit/157e960e2e64f3a7e3b03a507a88816ee3bb4186))
* **gen:** Fold the cfg and reference domains ([6df6991](https://github.com/Xevion/idakit/commit/6df6991b6dfee9baddcd78428ecba8896f93a518))
* **gen:** Fold the function domain into the generated bridge ([b6ad2c1](https://github.com/Xevion/idakit/commit/b6ad2c1818a3147163b1d227340be6cdaa308cba))
* **gen:** Fold the import domain into the generated bridge ([e3b7dda](https://github.com/Xevion/idakit/commit/e3b7ddaf4cd1c2a86f40ae5a15a354c56b9f89dc))
* **gen:** Fold the meta, export, name, and strings domains ([7c393b6](https://github.com/Xevion/idakit/commit/7c393b66d54bbcabb28072a25469d3e2ad7cb408))
* **gen:** Fold the range domain into the generated bridge ([bf74223](https://github.com/Xevion/idakit/commit/bf742232a11fc516ab5c88d37ffdc952fe7c1a53))
* **hexrays:** Decompile through the generated cxx handle ([db79d3e](https://github.com/Xevion/idakit/commit/db79d3ecf142810487f3731d6da54c7570942fe6))
* **idakit-sys:** Auto-fetch version-matched SDK headers via sparse git clone ([d946d18](https://github.com/Xevion/idakit/commit/d946d187be1b6e4ada89a9ad8b268735cfc1dbe1))
* **idakit:** Convert open to a builder and support headless auto-analysis ([d96919f](https://github.com/Xevion/idakit/commit/d96919f5be4097d3f0c301bd4cce26606afb008b))
* **idakit:** Implement Hash, Ord, Display, and Sub for core types ([3b9f288](https://github.com/Xevion/idakit/commit/3b9f288fdbdf862629ee3ae069715f6346602845))
* **idakit:** Trap IDA fatal exits and add CI infrastructure for integration tests ([3ec7fb6](https://github.com/Xevion/idakit/commit/3ec7fb66e7198bc9bd3d8eaada8b2f47827fe881))
* **idb:** Database metadata snapshot and name lookup ([d4ade4d](https://github.com/Xevion/idakit/commit/d4ade4db83473f67345f9bcd43602985f4783fca))
* **imports:** Add import/export enumeration via facade snapshot and typed iterators ([4be4a96](https://github.com/Xevion/idakit/commit/4be4a96303607de0d4b05d37380376bb0a8eeff6))
* **insn:** Code-gated Func::instructions() over all chunks ([af46090](https://github.com/Xevion/idakit/commit/af4609041dc50edc4fb89d1a0bc2b3948e4c62a8))
* **insn:** Decode through the generated cxx bridge ([4f864a6](https://github.com/Xevion/idakit/commit/4f864a68d01a7275a42713f4461a4a503499a36d))
* **insn:** Implement Idb::decode with mnemonic, operands, and control-flow facts for x86/x64 ([b88f421](https://github.com/Xevion/idakit/commit/b88f42132979011b9a82040857993bf22edd4538))
* **kernel:** Expose batch flag on IdaConfig, default on for headless bring-up ([cdff5af](https://github.com/Xevion/idakit/commit/cdff5af2f63ee16ae5d75a26fb0c8ebc86038c6d))
* **members:** Enum-constant edits ([a92b738](https://github.com/Xevion/idakit/commit/a92b738d9caba134939eee3085562cd09db05dc8))
* **members:** Struct and union member edits ([8331141](https://github.com/Xevion/idakit/commit/833114129921d38ccd0ae2e0b94fc8184a0df8b8))
* **name:** Return FunctionName sum type from Function::name() ([772089b](https://github.com/Xevion/idakit/commit/772089b4572eb6fc80f9ff1601629381ff02c027))
* **runtime:** Cover interr throw path in guarded&lt;&gt;, force TVHEADLESS on kernel bring-up ([2df2b90](https://github.com/Xevion/idakit/commit/2df2b90681ccc6b9fcba584f84643043486f6735))
* **runtime:** Extend fatal traps to abort(), add trap and fault-injection test suites ([71fdafd](https://github.com/Xevion/idakit/commit/71fdafd53147dfa41d3ad9ac4e32afb26725b85f))
* **search:** Add binary pattern search with Pattern and Matches iterator ([c9f039f](https://github.com/Xevion/idakit/commit/c9f039fa11ce6640154adb4e236479b086e7c9c8))
* **strings:** Add Strings iterator and StringLiteral view over IDA's strlist ([c4bd094](https://github.com/Xevion/idakit/commit/c4bd0945b11581dd791b02131a5c893b7f9c9ba5))
* **sys:** Add rename and comment writes ([edb552d](https://github.com/Xevion/idakit/commit/edb552dc31f033a7406196a04a31400667928aeb))
* **sys:** Bind idalib lifecycle ([25f7ef2](https://github.com/Xevion/idakit/commit/25f7ef2eaf4fad75ec7a2f1c38b7135aefc3ce78))
* **sys:** Productionize the interr-aware trycatch ([10bb81c](https://github.com/Xevion/idakit/commit/10bb81cce29fcb3f55e42bc7640b58a33390172e))
* **ty:** Drive type walks through the cxx visitor ([9cc27f7](https://github.com/Xevion/idakit/commit/9cc27f75e52fa48b4efd8b8bf6cc50b0b1e05eaa))
* **types:** Add Opaque variant for named-but-bodyless types and handle bitfields ([b423b15](https://github.com/Xevion/idakit/commit/b423b151dd9b509f1d81c5a32ba5987c5829085d))
* **types:** Cross-database type diff via CanonicalType, TypeCatalog, and ordinal enumeration ([501939a](https://github.com/Xevion/idakit/commit/501939af515e96f8e094fa35a04ac4f40cacac93))
* **types:** Extract shared type walker and add structured frame type walk ([02e0e49](https://github.com/Xevion/idakit/commit/02e0e49a44ca04a0b65bf4e111b3a869d59ab0c4))
* **write:** Clear_type on location and function cursors ([a3dc95f](https://github.com/Xevion/idakit/commit/a3dc95f5b100a62bc9dcfca707a416f6ece5f3d2))
* **write:** Cursors, type-apply, and define ([93b68a4](https://github.com/Xevion/idakit/commit/93b68a45b7bdf516b7d6122526091c3ae2fd7b62))
* **xref:** Lazy xref cursor with xrefs_to/xrefs_from on Idb and Func ([617fd66](https://github.com/Xevion/idakit/commit/617fd66ef555d7222f7aa08e91659002f36722d3))
* **xref:** Surface reference origin (user vs IDA analysis) ([0ff9cbf](https://github.com/Xevion/idakit/commit/0ff9cbfe7f1f8ca3bf6fb9ba39c94b6e05a62b94))


### Bug Fixes

* **build:** Fail clearly when the ida runtime is missing ([b7b7a79](https://github.com/Xevion/idakit/commit/b7b7a792678e5ffdf8bcca11f254955ce7fd45c6))
* **ci:** Suppress the verified-benign TSan lock-order detail, re-gate thread mode ([b60db82](https://github.com/Xevion/idakit/commit/b60db821b33f71eafc013770085b7f9826f8f76e))
* **corpus:** Return exit code from main so the banner swallow runs on Windows ([ea81f72](https://github.com/Xevion/idakit/commit/ea81f72de9b8c4fcd8629e8dfb48c7f653a0b72c))
* **ctree:** Assert decompile extraction against visitor-minus-elided-empties ([3e943e0](https://github.com/Xevion/idakit/commit/3e943e06cb625d1bd42cfbe8e445a2e6c6b9c412))
* **docs:** Escape example doc-comment placeholders, lint them in `just check` ([cfad3d3](https://github.com/Xevion/idakit/commit/cfad3d3216baac9e3ce8a555eadc2f21f737054c))
* **facade:** Null-terminate pseudocode when it fills the buffer ([1bb7dd3](https://github.com/Xevion/idakit/commit/1bb7dd32915e4bbca6245c3ffc478961722f1aba))
* **facade:** Read the ui_msg va_list portably across target ABIs ([6906f01](https://github.com/Xevion/idakit/commit/6906f019f89f08900c87ca10c96d17ae864a8e35))
* **facade:** Resolve all clang-tidy warnings, enforce warnings-as-errors in CI ([bb3b235](https://github.com/Xevion/idakit/commit/bb3b235f792f954424e84e6b66e4b0efb592f39b))
* **facade:** Switch stdout/stderr capture from tmpfile to non-blocking pipe ([4e0078c](https://github.com/Xevion/idakit/commit/4e0078c64899cbf5d4ab8c46fcf999fd522aa593))
* **idakit-sys:** Avoid passing BADSIZE sentinel as scalar byte width in facade ([bdb97f5](https://github.com/Xevion/idakit/commit/bdb97f54ea43a929c6d7c5e284cd8aba20bd5831))
* **idakit-sys:** Catch C++ exceptions in all facade entry points and abort ([102cde2](https://github.com/Xevion/idakit/commit/102cde23f33ebce402a3f159383c2b5d696849c3))
* **test:** Add common test_db helper with IDADIR fallback, swallow IDA exit banner ([b8c3610](https://github.com/Xevion/idakit/commit/b8c361081490940dba627bcd3172a052aa84b486))
* **ty:** Harden type construction against bad input ([cb3f51d](https://github.com/Xevion/idakit/commit/cb3f51d1b195649f7f5592591b48a62ff09239fd))


### Code Refactoring

* **api:** Replace Ea/func/insn/xref abbreviations with unambiguous full names ([e3ca795](https://github.com/Xevion/idakit/commit/e3ca79592606d5121591fc03d0267673df18ef11))
* **build:** Factor per-bridge cxx wiring into one helper ([3e0579b](https://github.com/Xevion/idakit/commit/3e0579b3fc353187118576c82b976dc2c1f101b3))
* **build:** Replace Linux-hardcoded paths and ifdefs with per-OS platform constants ([ebec425](https://github.com/Xevion/idakit/commit/ebec425adf2724492ae3f2e72d5e156ccc91dc92))
* **core:** Decouple kernel from OS main thread and centralise FFI ([066b114](https://github.com/Xevion/idakit/commit/066b11419f6b3e05c7c135ac8ff2ba4218762e32))
* **core:** Replace panics with structured error types across kernel boundary ([d78bcc9](https://github.com/Xevion/idakit/commit/d78bcc95a5f24b1c9a2413f2e97038284295bd7e))
* **ctree:** Rename offset to byte_offset, add tracing, and improve docs ([8eb2c1d](https://github.com/Xevion/idakit/commit/8eb2c1dfa7e34d4ff544d9dbf4233541f0f01f6f))
* **ctree:** Replace flat record extraction with streaming vtable walk ([555de77](https://github.com/Xevion/idakit/commit/555de77e3e0facdd52c87b324736ae6d5502fafa))
* **facade:** Decompose idakit_facade.cpp into db, decode, hexrays, types, runtime ([b020ef3](https://github.com/Xevion/idakit/commit/b020ef3efa4477685ba183929803bb9e03eae512))
* **facade:** Fold the two named-type load helpers into one ([200246b](https://github.com/Xevion/idakit/commit/200246b8cdff6096174add704071cf1e4f8e70d2))
* **gen:** Build the multi-domain cxx-gen generator ([808e9dd](https://github.com/Xevion/idakit/commit/808e9ddd5a5bccfcf3f72c9991ab1a0738177a7d))
* **idakit-sys:** Extract FFI declarations into domain modules, re-export flat ([78c1df0](https://github.com/Xevion/idakit/commit/78c1df03fdb7ab6e9edca851a18cccc16baf7a41))
* **idakit:** Flip the read path onto the generated bridge ([0c43ae9](https://github.com/Xevion/idakit/commit/0c43ae9d1f8c69071386bfa24d91df5c35231e4b))
* **search:** Expand Pattern API with named constructors and structured PatternRejection ([e25a661](https://github.com/Xevion/idakit/commit/e25a6619ccae00fa9371c457f9e4fd6860b7c30c))
* **sys:** Delete the raw facade ([943ecd8](https://github.com/Xevion/idakit/commit/943ecd8bb976c7326370d3affe2b8946be5e92bc))
* **sys:** Group ffi declarations by origin ([eaaa916](https://github.com/Xevion/idakit/commit/eaaa91650244eabb9f50f52c528b7d13f1d9114b))
* **sys:** Strip the cfunc spike to its inline path ([b7ea7fc](https://github.com/Xevion/idakit/commit/b7ea7fcf70b8548ab6491f8737f00ccedf8094a0))
* **test:** Convert harness=false tests to #[test] via Ida::run, serialize with nextest ([3dd30ba](https://github.com/Xevion/idakit/commit/3dd30ba965673e93d2002ac5cebc3969e8dc0a58))
* **ty:** Flip the write side onto the generated bridge ([ab8cc93](https://github.com/Xevion/idakit/commit/ab8cc93e8fcc67389117d7372c713f6f426c0d02))
* **types:** Replace kernel-bound TypeInfo with Send TypeImage backed by interned TypeTable ([74202e2](https://github.com/Xevion/idakit/commit/74202e2701637ff598b1eca3f0e501bc9d361b65))


### Documentation

* **idakit:** Reflow and restructure doc comments crate-wide ([c78281a](https://github.com/Xevion/idakit/commit/c78281a5324484f57d66bc504862abb112ca2dff))
* **idakit:** Rewrite crate front page and README ([ba8ce1f](https://github.com/Xevion/idakit/commit/ba8ce1f564222254995c2615d3a292a566693ff6))
* Make crates publishable — metadata, deny(missing_docs), README, docs.rs ([3bf7b4b](https://github.com/Xevion/idakit/commit/3bf7b4bc9ecea300c0ca9cbf27754ab2ef39ea98))
* Tidy comments across the cxx overhaul ([ac05ec2](https://github.com/Xevion/idakit/commit/ac05ec2dc2b94f4633663b1e87eb26ce017f3dd2))


### Continuous Integration

* **cpp:** Add clang-format/clang-tidy via mise, reformat facade, wire C++ checks into CI ([8b08f1d](https://github.com/Xevion/idakit/commit/8b08f1d62c7b990ba02f65cd6ff9000da7349d08))
* **docs:** Enforce rustdoc lints via deny attributes, just doc recipe, and CI step ([50ff9d9](https://github.com/Xevion/idakit/commit/50ff9d92334c6c945d96921581a21e45e999842c))
* **release:** Wire release-please and crates.io publish pipeline ([cd00924](https://github.com/Xevion/idakit/commit/cd0092473eec960c4fb3f5814271153fb5bef09d))


### Build System

* **idakit-sys:** Discover IDADIR robustly instead of one hardcoded path ([28286aa](https://github.com/Xevion/idakit/commit/28286aa30d79747fb8334a66aa756445bf6689a1))
* **sys:** Compile c++ facade against the ida sdk ([8bb3db6](https://github.com/Xevion/idakit/commit/8bb3db63877e18b0437e711e381b39ee25bdbe17))


### Miscellaneous

* **ci:** Add sanitizer, pedantic, and clang-tidy-cache passes ([352438f](https://github.com/Xevion/idakit/commit/352438fe4b042c9883942463e754155b7394c62f))
* **ci:** Add step names, parallelize fixture downloads, scope clang configs to idakit-sys ([83e5b82](https://github.com/Xevion/idakit/commit/83e5b8289e1c339cb792dc407404d3ff9b3023a0))
* **cxx:** Restore the cxx-interop spike as the overhaul baseline ([50f2f77](https://github.com/Xevion/idakit/commit/50f2f7743fd8419122edcc1ac0f38d5c7f299aba))
* **types:** Retire type/frame string APIs, add tag_name accessor ([7b1f73f](https://github.com/Xevion/idakit/commit/7b1f73f03c0ac2be39f37a8c9e8fb9b9989f89ec))
* **workspace:** Initialize cargo workspace ([32a1308](https://github.com/Xevion/idakit/commit/32a1308b9846d6437b5d5d2b8c43fc4f042aeae5))
