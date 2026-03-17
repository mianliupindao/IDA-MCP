# IDA-MCP Roadmap

## Background

IDA-MCP already covers core reads, decompilation/disassembly, renaming/comments, stack editing, type application, debugger control, and `py_eval`.

`py_eval` remains the escape hatch for many common IDAPython workflows. This roadmap focuses on replacing those workflows with stable MCP tools first, instead of broadening the surface area indiscriminately.

## Principles

- Prefer tools that remove recurring `py_eval` usage.
- Prefer structured JSON results over string-only outputs.
- Keep proxy and direct-instance parameter names aligned.
- Add first-class tools only when existing tools cannot express the workflow cleanly.
- Every new tool should ship with proxy exposure, README updates, and tests.

## Current Gaps Still Commonly Solved With `py_eval`

- Database shaping: create/delete functions, convert bytes to code/data/string, undefine ranges.
- Finer-grained type editing: struct member CRUD, enum member CRUD.
- Structured analysis: callers/callees, function-level CFG, line-based pseudocode output, structured signatures.
- Engineering workflow helpers: patch export/revert, function/pseudocode comments, UI navigation helpers.
- Resource parity: `ida://` resources still cover only part of the read surface and are direct-instance only.

## Phased Delivery

### Tranche 0: Baseline and Tracking

Goal: define the reduction target and keep the implementation phased.

- Track the main `py_eval` replacement targets listed above.
- Keep completion criteria uniform across tranches:
  - direct IDA tool exists
  - proxy forwards it
  - README/README_CN list it
  - tests cover the new behavior

### Tranche 1: Modeling APIs

Goal: reduce the highest-frequency database-shaping `py_eval` snippets.

Deliver:

- `create_function(address, end?)`
- `delete_function(address)`
- `make_code(address)`
- `undefine_items(address, size)`
- `make_data(address, data_type, count=1)`
- `make_string(address, string_type="c", length?)`
- `create_array(address, item_type, count)`

Acceptance:

- Existing functions return idempotent results for `create_function`.
- Existing code returns idempotent results for `make_code`.
- Invalid addresses/types/counts fail cleanly.
- Data/string/code creation can replace existing items without requiring `py_eval`.

### Tranche 2: Type Editing APIs

Goal: remove common `py_eval` usage around struct and enum editing.

Deliver:

- `create_struct(name, is_union?)`
- `delete_struct(name)`
- `add_struct_member(struct_name, name, offset, member_type, size?)`
- `delete_struct_member(struct_name, name)`
- `rename_struct_member(struct_name, old_name, new_name)`
- `set_struct_member_type(struct_name, name, new_type)`
- `create_enum(name)`
- `add_enum_member(enum_name, name, value)`
- `delete_enum_member(enum_name, name)`

Acceptance:

- Struct and enum member edits are possible without writing IDAPython snippets.
- Results expose whether the target already existed and whether the database changed.

### Tranche 3: Structured Analysis APIs

Goal: replace string scraping and ad hoc `py_eval` for higher-level analysis.

Deliver:

- `get_callers(function)`
- `get_callees(function)`
- `get_function_cfg(function)`
- `get_pseudocode_lines(function)`
- `get_function_signature(function)`

Acceptance:

- Call relationships are returned at function granularity.
- CFG output is machine-friendly and not just raw text.
- Pseudocode and signature output are available in structured form alongside existing text tools.

### Tranche 4: Engineering Completion

Goal: close the loop on editing and navigation workflows.

Deliver:

- `set_function_comment(...)`
- `set_pseudocode_comment(...)` if Hex-Rays APIs prove stable enough
- `export_patches(...)`
- `revert_patches(...)`
- `jump_to(address)`
- `get_selection()`

Acceptance:

- Common edit/export/navigation tasks no longer require `py_eval`.
- Any deferred Hex-Rays-specific capability is documented explicitly instead of remaining implicit.

## Exit Criteria

This roadmap is succeeding when the recommended path for common IDA automation is a dedicated MCP tool, not a hand-written `py_eval` snippet.
