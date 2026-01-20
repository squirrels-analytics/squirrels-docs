from __future__ import annotations

from typing import Type, Optional, Any, Iterator
import importlib.util
from contextlib import contextmanager
from pathlib import Path
import sys

from . import _constants as c, _utils as u
from ._exceptions import ConfigurationError, FileExecutionError


@contextmanager
def _temporary_sys_path(path: str) -> Iterator[None]:
    """
    Temporarily prepend `path` to sys.path for the duration of the context.
    """
    resolved = str(Path(path).resolve())
    prior = list(sys.path)
    try:
        if resolved in sys.path:
            # Ensure it is first, so imports resolve to this project before anything else.
            sys.path.remove(resolved)
        sys.path.insert(0, resolved)
        yield
    finally:
        sys.path[:] = prior


@contextmanager
def _temporary_sys_modules(prefixes: tuple[str, ...]) -> Iterator[None]:
    """
    Temporarily isolate sys.modules entries for certain prefixes.

    This prevents cross-project pollution when multiple SquirrelsProject instances
    in the same process import identically named packages (e.g. "pyconfigs").
    """
    def _matches(name: str) -> bool:
        return any(name == p or name.startswith(p + ".") for p in prefixes)

    saved: dict[str, Any] = {k: v for k, v in sys.modules.items() if _matches(k)}
    try:
        # Remove matching modules so imports during this block re-resolve.
        for k in list(sys.modules.keys()):
            if _matches(k):
                sys.modules.pop(k, None)
        yield
    finally:
        # Remove any modules added during this block for the prefixes.
        for k in list(sys.modules.keys()):
            if _matches(k):
                sys.modules.pop(k, None)
        # Restore prior state.
        sys.modules.update(saved)


class PyModule:
    def __init__(
        self,
        filepath: u.FilePath,
        project_path: str,
        *,
        default_class: Optional[Type] = None,
        is_required: bool = False,
    ) -> None:
        """
        Constructor for PyModule, an abstract module for a file that may or may not exist
        
        Arguments:
            filepath (str | pathlib.Path): The file path to the python module
            project_path: The root folder of the Squirrels project. If provided, it is temporarily
                added to sys.path while executing the module so imports like `from pyconfigs import user`
                can work without globally mutating sys.path.
            is_required: If true, throw an error if the file path doesn't exist
        """
        self.filepath = str(filepath)
        try:
            with _temporary_sys_path(project_path), _temporary_sys_modules((c.PYCONFIGS_FOLDER, c.PACKAGES_FOLDER)):
                spec = importlib.util.spec_from_file_location(self.filepath, self.filepath)
                assert spec is not None and spec.loader is not None
                self.module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(self.module)
        except FileNotFoundError as e:
            if is_required:
                raise ConfigurationError(f"Required file not found: '{self.filepath}'") from e
            self.module = default_class
    
    def get_func_or_class(self, attr_name: str, *, default_attr: Any = None, is_required: bool = True) -> Any:
        """
        Get an attribute of the module. Usually a python function or class.

        Arguments:
            attr_name: The attribute name
            default_attr: The default function or class to use if the attribute cannot be found
            is_required: If true, throw an error if the attribute cannot be found, unless default_attr is not None
        
        Returns:
            The attribute of the module
        """
        func_or_class = getattr(self.module, attr_name, default_attr)
        if func_or_class is None and is_required:
            raise ConfigurationError(f"Module '{self.filepath}' missing required attribute '{attr_name}'")
        return func_or_class


def run_pyconfig_main(project_path: str, filename: str, kwargs: dict[str, Any] = {}) -> Any | None:
    """
    Given a python file in the 'pyconfigs' folder, run its main function
    
    Arguments:
        project_path: The base path of the project
        filename: The name of the file to run main function
        kwargs: Dictionary of the main function arguments
    """
    filepath = u.Path(project_path, c.PYCONFIGS_FOLDER, filename)
    module = PyModule(filepath, project_path)
    main_function = module.get_func_or_class(c.MAIN_FUNC, is_required=False)
    if main_function:
        try:
            return main_function(**kwargs)
        except Exception as e:
            raise FileExecutionError(f'Failed to run python file "{filepath}"', e) from e
