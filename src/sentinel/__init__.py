from importlib.metadata import version, PackageNotFoundError

try:
    __version__: str = version("sentinel-scanner")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"
