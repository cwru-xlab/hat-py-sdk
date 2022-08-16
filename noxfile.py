import tempfile
from typing import Any

import nox
from nox.sessions import Session

package = "hat"
nox.options.sessions = "lint", "safety", "mypy", "pytype", "tests"
# locations = "src", "tests", "noxfile.py"
locations = "src", "noxfile.py"
py_versions = ("3.7", "3.8", "3.9")


def install_with_constraints(session: Session, *args: str, **kwargs: Any) -> str:
    """Install packages constrained by Poetry's lock file. This function is a
    wrapper for nox.sessions.Session.install. It invokes pip to install
    packages inside the session's virtualenv. Additionally, pip is passed a
    constraints file generated from Poetry's lock file, to ensure that the
    packages are pinned to the versions specified in poetry.lock. This allows
    you to manage the packages as Poetry development dependencies.

    Args:
        session: The Session object.
        args: Command-line arguments for pip.
        kwargs: Additional keyword arguments for Session.install.
    """
    with tempfile.NamedTemporaryFile() as requirements:
        session.run(
            "poetry",
            "export",
            "--dev",
            "--format=requirements.txt",
            "--without-hashes",
            f"--output={requirements.name}",
            external=True,
        )
        session.install(f"--constraint={requirements.name}", *args, **kwargs)
        return requirements.name


@nox.session(py="3.9")
def black(session: Session) -> None:
    """Run black code formatter."""
    install_with_constraints(session, "black")
    session.run("black", *run_args(session))


@nox.session(py=py_versions)
def lint(session: Session) -> None:
    """Lint using flake8."""
    install_with_constraints(
        session, "flake8", "flake8-black", "flake8-bugbear", "flake8-import-order"
    )
    session.run("flake8", *run_args(session))


@nox.session(python=py_versions)
def safety(session: Session) -> None:
    """Scan dependencies for insecure packages."""
    filename = install_with_constraints(session, "safety")
    session.run("safety", "check", f"--file={filename}", "--full-report")


def run_args(session: Session) -> list[str]:
    return session.posargs or locations
