import functools
import inspect
import logging
import os
from io import open

from ruamel.yaml import YAML

from kordesii.core import DECODER_OUTPUT_DIR

yaml = YAML(typ='safe')
yaml.default_flow_style = False
log = logging.getLogger(__name__)

_serializers = {}


class ROObject(object):
    """Basic class represent deserialized objects that are read-only."""

    def __init__(self, adict):
        self.__dict__.update(adict)

    def __repr__(self):
        if 'repr' in self.__dict__:
            return self.__dict__['repr']

        repr_str = "<{}.{}<{}> at {:#8x}>".format(
            self.__module__, self.__class__.__name__,
            self.__dict__.get('__yaml_name__'), id(self))

        return repr_str

    def __setattr__(self, key, value):
        raise RuntimeError("Cannot modify attributes of Read Only Objects.")

    @classmethod
    def from_yaml(cls, constructor, node):
        return cls(dict(constructor.construct_pairs(node)))


yaml.constructor.add_constructor(u'!ReadOnlyObject', ROObject.from_yaml)


def obj_to_yaml(representer, node, yaml_name=None, skip_attrs=None):
    """
    Generic YAML representer function. Converts the arbitrary class instance to a
    ReadOnlyObject formatted YAML representation.

    By default this captures every non-private, non-function attribute of the class instance.
    This includes any properties set with ``@property`` or ``property()``.

    :param ruamel.yaml.representer.BaseRepresenter representer: YAML representer
    :param node: Class instance to represent in YAML
    :param yaml_name: Optional tag for YAML serialization
    :param skip_attrs: Attributes to skip serializing
    :return: YAML representation object for node
    """
    skip_attrs = skip_attrs or []
    members = {}
    # Adapted from inspect.getmembers()
    for key in dir(node):
        if key.startswith('_') or key in skip_attrs:
            continue
        try:
            value = getattr(node, key)
        except AttributeError:
            continue
        if not inspect.isroutine(value):
            members[key] = value

    if '__yaml_name__' not in members:
        yaml_name = yaml_name or node.__class__.__name__
        members['__yaml_name__'] = yaml_name

    return representer.represent_mapping(u'!ReadOnlyObject', members)


def serializable_class(cls=None, yaml_name=None, skip_attrs=None, func=None):
    """
    Class decorator for arbitrary YAML-serializable classes.

    Optionally takes a function as an argument to overwrite the generic
    `obj_to_yaml` or the class's `to_yaml` function.
    This function must also be a valid YAML representer function.

    If a function is not specified, the class function `to_yaml` will be used
    if it exists. Otherwise, the generic `obj_to_yaml` will be used.
    """

    # A wrapper is needed for the case of using arguments in the decorator
    def _wrapper(klass):
        yaml_func = func  # separate variable to avoid strange wrapper reference issues
        if yaml_func is None:
            if hasattr(klass, 'to_yaml'):
                yaml_func = klass.to_yaml
            elif yaml_name is None and skip_attrs is None:
                yaml_func = obj_to_yaml
            else:
                yaml_func = functools.partial(obj_to_yaml, yaml_name=yaml_name, skip_attrs=skip_attrs)
        yaml.representer.add_representer(klass, yaml_func)
        return klass

    if cls is None:
        return _wrapper

    return _wrapper(cls)


class Serializer(object):
    """
    Do not access directly, instead, access via ``get_serializer()``.

    Serialization object. To be used within decoders to save arbitrary
    data that can later be used in an MWCP parser or elsewhere.

    Serialized data is saved as YAML to `other_data.yml` in the decoder output directory.

    A Serializer instance acts somewhat similarly to a dictionary, with the caveat that
    all keys are **write once**.

    Note: data is serialized and saved **when set**, so if a class is stateful,
    the version at the time of the key referring to that instance
    being set is the version saved, even if it is
    modified later. This also means that if that instance is retrieved from the Serializer
    later, it may not be the same version as what was saved. The best practice is
    to only serialize an instance when it will no longer be modified (e.g. right before
    the decoder is finished.) This should only be a real concern for EncodedString
    and EncodedStackString.
    """

    def __init__(self, name='other_data'):
        self._data = {}

        # Normally the output directory hasn't been created yet when the Serializer is
        # first initialized.
        if not os.path.isdir(DECODER_OUTPUT_DIR):
            os.makedirs(DECODER_OUTPUT_DIR)

        self._filepath = os.path.join(DECODER_OUTPUT_DIR, name + '.yml')
        self._name = name

        self._file = None

    def __del__(self):
        """
        Close the file when the Serializer object is deleted or garbage collected
        (including termination of the decoder).
        """
        if self._file is not None and not self._file.closed:
            self._file.close()

    def __getitem__(self, item):
        return self._data[item]

    def __setitem__(self, key, value):
        return self.set(key, value)

    def __contains__(self, item):
        return item in self._data

    def __repr__(self):
        return '<Serializer with keys: {!r}>'.format(self._data.keys())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def keys(self):
        """List of all keys serialized."""
        return self._data.keys()

    def values(self):
        """List of all values serialized."""
        return self._data.values()

    def items(self):
        """Tuple of (key, value) all pairs serialized."""
        return self._data.items()

    def get(self, key, default=None):
        """Retrieve a previously saved key. Accepts a default."""
        return self._data.get(key, default)

    def set(self, key, value):
        """
        Set a key-value pair and serialize them.

        Keys may only be set once, a `ValueError` will be raised
        if attempting to set a previously set key.

        The pair is saved to the serialization file immediately.

        :param key: Any YAML-valid key, like a string or number
        :param value: Arbitrary value to serialize, must be YAML compatible
        :raises ValueError: A used key is attempted to be used again
        """
        if key in self._data:
            log.error("Key '{}' attempted to be set twice in serializer '{}'.".format(key, self._name))
            raise ValueError("A key may only be set once.")
        self._data[key] = value
        self._save(key, value)

        log.debug("Set key {} in serializer".format(key))

    def _save(self, key, value):
        if self._file is None:
            self._file = open(self._filepath, 'w', encoding='utf8', newline='\n')
        yaml.dump({key: value}, self._file)


def get_serializer(name='other_data'):
    """
    Generally we want only one Serializer object per kordesii instance to avoid
    clobbering the serialized data each write.

    :param str name: Name of the serializer, should not normally need to be changed.
    :return: Serializer object
    :rtype: Serializer
    """
    global _serializers
    if name not in _serializers:
        _serializers[name] = Serializer(name)
    return _serializers[name]


def deserialize(yml_data):
    """
    Deserialize data from the given YAML data.

    :param bytes or str yml_data: Data from the serialization file
    :return: Dict of the deserialized data
    :rtype: dict
    """
    if not yml_data:
        return {}
    try:
        return yaml.load(yml_data)
    except Exception as e:
        log.error("Error loading serialization file: {}".format(str(e)))
        return {}
