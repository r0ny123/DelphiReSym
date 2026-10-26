# Recovery regression checks

These tests are added by the metadata-recovery patch; upstream main did not have a test suite.
Run the six Python regression cases without Ghidra:

```sh
python -m unittest discover -s tests -v
```

For full application, install PyGhidra, select a supported JDK, and run against a local Delphi PE with recoverable TObject metadata:

```sh
python tests/ghidra_application.py sample.exe --ghidra /path/to/ghidra_12.2_PUBLIC --output application.json
```

This imports and analyzes the PE in Ghidra, applies DelphiReSym twice inside database transactions,
and records resulting function names, namespaces, signatures and parameter counts. It also checks the
UInt64 width, defined VT pointer components and TObject.Create/Free Self parameters. It does not
execute the input PE. Inspect `changed_second_pass` to identify differences between applications;
a successful run alone does not establish semantic correctness for every recovered type.

The application assertions exercise selected known signatures and layout widths. They do not
provide source-level ground truth for every recovered method, ABI, runtime string layout or
compiler version. The runner retains the source hash in its output so results can be tied to
the exact script tested.
