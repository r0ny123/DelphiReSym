"""Run real Ghidra analysis and two metadata application passes on a supplied PE."""
import argparse
import hashlib
import json
import sys
import types
from pathlib import Path
from tempfile import TemporaryDirectory

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('--ghidra', required=True)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
import pyghidra
pyghidra.start(install_dir=args.ghidra)
from pyghidra.core import _setup_project, _analyze_program
from pyghidra.api import transaction
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor

source = Path(__file__).parents[1] / 'src/ghidra_scripts/DelphiReSym.py'
with TemporaryDirectory() as location:
    project, program = _setup_project(args.binary, project_location=location)
    flat = FlatProgramAPI(program)
    _analyze_program(flat, program)
    print("Ghidra auto-analysis complete", flush=True)
    module = types.ModuleType('delphi_application_test')
    sys.modules[module.__name__] = module
    module.__dict__.update(currentProgram=program, monitor=TaskMonitor.DUMMY,
                           toAddr=flat.toAddr, createFunction=flat.createFunction,
                           createClass=flat.createClass, getFunctionAt=flat.getFunctionAt)
    source_text = source.read_text()
    source_sha256 = hashlib.sha256(source_text.encode()).hexdigest()
    exec(compile(source_text.rsplit('if pyghidra.started():', 1)[0], str(source), 'exec'), module.__dict__)
    module.VERBOSE_INFO = False
    assert module.prepare_data_type("UInt64").data_type.getLength() == 8
    snapshots = []
    for iteration in range(2):
        print(f"Applying Delphi metadata, pass {iteration + 1}", flush=True)
        with transaction(program, 'Delphi recovery verification'):
            module.main()
        snapshots.append({str(f.getEntryPoint()): {'name': str(f.getName(True)),
                         'signature': str(f.getSignature()),
                         'parameters': int(f.getParameterCount())}
                         for f in program.getFunctionManager().getFunctions(True)})
    for method in ('Create', 'Free'):
        function = next(f for f in program.getFunctionManager().getFunctions(True)
                        if str(f.getName(True)) == 'System::TObject::' + method)
        assert function.getParameterCount() == 1
        parameter = function.getParameter(0)
        assert str(parameter.getName()) == 'Self'
        assert parameter.getDataType().getLength() == program.getDefaultPointerSize()
        assert 'TObject' in str(parameter.getDataType().getName())
    vt_components = 0
    for datatype in program.getDataTypeManager().getAllDataTypes():
        if datatype.getName().startswith('VT_') and hasattr(datatype, 'getDefinedComponents'):
            for component in datatype.getDefinedComponents():
                assert component.getLength() == program.getDefaultPointerSize()
                assert component.getDataType().getLength() == program.getDefaultPointerSize()
                vt_components += 1
    assert vt_components > 0
    result = {'source_sha256': source_sha256, 'verified_vt_components': vt_components, 'binary': args.binary.name, 'first_functions': len(snapshots[0]),
              'second_functions': len(snapshots[1]),
              'changed_second_pass': sum(snapshots[0].get(k) != v for k, v in snapshots[1].items()),
              'functions': snapshots[1]}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print({k: v for k, v in result.items() if k != 'functions'}, flush=True)
