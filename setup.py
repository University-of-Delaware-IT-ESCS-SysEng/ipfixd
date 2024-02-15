from distutils.core import setup
from Cython.Build import cythonize

setup(
    name = 'ipfixd',
    ext_modules = cythonize( 'ipfixd_app/*.pyx',
    include_path=[ 'ipfixd_app' ],
    language_level = "3" )
)
