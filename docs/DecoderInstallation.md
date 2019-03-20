# Decoder Installation Guide

- [Adding a Directory](#adding-a-directory)
- [Formal Packaging](#formal-packaging)


### Guides
- [Decoder Development](DecoderDevelopment.md)
- [Decoder Installation](DecoderInstallation.md)
- [Decoder Testing](DecoderTesting.md)


## Adding a Directory
To install your own custom decoder by directory, please follow these steps:

1. Place all your decoders into a directory. If you would like to use sub directories
make sure to include `__init__.py` files so Python can see them as packages.
*(Files starting with `_` will be ignored.)*

1. Then pass the directory containing your parsers to the DC3-Kordesii tool being used.

```console
> kordesii --decoder-dir=C:\my_decoders parse <name> <input_file>
```

You should then find your parsers available alongside the default parsers that come with Kordesii using
the `kordesii list` command.

```console
> kordesii --decoder-dir=C:\my_decoders list
NAME            SOURCE          AUTHOR    DESCRIPTION
--------------  --------------  --------  -------------------------------------
Sample          kordesii        DC3       Sample decoder
stack_string    kordesii        DC3       Extracts stack strings
Foo             C:\my_decoders  ACME      ACME foo decoder
```

For more persistence, you can add the environment variable `KORDESII_DECODER_DIR` which points 
to your parser directory. This will cause `--decoder-dir` to automatically apply if not supplied. 

```console
> set KORDESII_DECODER_DIR="C:\my_parsers"
> kordesii parse Foo ./malware.bin
> kordesii list
```


## Formal Packaging
If you would like to package your decoders in a more formal and shareable way,
DC3-Kordesii supports the use of setuptool's entry_points to register decoders from within
your own python package.

This allows for a number of benefits:
- Provides a way to encapsulate your decoders as a proper python project.
- Gives users an easy way to install kordesii and your parsers at the same time. (pip installable)
- Allows you to specify what versions of kordesii your decoders support.
- Allows you to easily specify and install extra dependencies your decoders require.
- Allows you to maintain versions of your decoders.
- Provides a way to distribute and maintain extra helper/utility modules that are used by your decoders.

To set this up, structure your decoders into a package and include a `setup.py` file to declare it as a python project.

It should look something like this:
```
some_root_dir/
|- README.md
|- setup.py
|- kordesii_acme/
|   |- __init__.py
|   |- decoders/
|   |   |- __init__.py
|   |   |- baz.py
|   |   |- foo.py
|   |   |- tests/  # Tests should be found within the root of your parsers package with the name "tests"
|   |   |   |- baz.json
|   |   |   |- foo.json
```


Then, within your `setup.py` file, declare an entry_point for "kordesii.decoders" pointing
to the package containing your parsers. The name set before the "=" will be the source name for
the decoders contained within. *(Your project may create multiple entry points provided they
have unique source names)*

```python
# in setup.py

from setuptools import setup, find_packages


setup(
    name='kordesii-acme',
    description='DC3-Kordesii decoders developed by ACME inc.',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'kordesii.decoders': [
            'acme = kordesii_acme.decoders',
        ]
    },
    install_requires=[
        'kordesii>=1.4.0',
        # Add any other requirements needed for this group of parsers here.
    ]
)
```


*(More information about setuptools can be found here: [https://setuptools.readthedocs.io]())*

Then, install your package.
```console
> cd some_root_dir
> pip install .
```

Your decoders should now be available alongside the default decoders and any other kordesii decoder projects.
```console
> kordesii list
NAME            SOURCE          AUTHOR    DESCRIPTION
--------------  --------------  --------  -------------------------------------
Sample          kordesii        DC3       Sample decoder
stack_string    kordesii        DC3       Extracts stack strings
foo             acme            ACME      ACME foo decoder
Sample          acme            ACME      ACME Sample decoder
```


NOTE: If multiple kordesii projects contain parsers with the same name (case-sensitive), then all decoders with that name will be run back-to-back.
```console
> kordesii parse Sample <input>   # Will run the "Sample" decoder from both kordesii and ACME.
```

To specify a particular decoder, you can provide the source name using ":" notation.
```console
> kordesii parse acme:Sample <input>  # Will run the "Sample" decoder from ACME only.
```


Alternatively you can specify the source with the `--decoder-source` flag or by creating
a `KORDESII_DECODER_SOURCE` for more persistence.
```console
> kordesii --decoder-source=acme parse Sample <input>
OR
> set KORDESII_DECODER_SOURCE="acme"
> kordesii parse Sample <input>
```

