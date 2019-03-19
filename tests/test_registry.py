"""Tests decoder registration functionality."""

import os

import kordesii
from kordesii.decoder import Decoder


def test_register_decoder_directory(monkeypatch, Sample_decoder):
    # Monkey patch decoders registration so previous test runs don't muck with this.
    monkeypatch.setattr('kordesii.registry._sources', {})

    decoder_dir = os.path.dirname(Sample_decoder)

    # Test registration
    assert not list(kordesii.iter_decoders('Sample'))
    kordesii.register_decoder_directory(decoder_dir)
    decoders = list(kordesii.iter_decoders('Sample'))
    assert len(decoders) == 1

    # Test it was registered properly
    decoder = decoders[0]
    assert decoder.name == 'Sample'

    # Test we can also pull by source name.
    decoders = list(kordesii.iter_decoders(source=decoder_dir))
    assert len(decoders) == 1
    decoders = list(kordesii.iter_decoders(decoder_dir + ':'))
    assert len(decoders) == 1
    
    
def test_register_decoder_directory2(monkeypatch, Sample_decoder):
    # Monkey patch decoders registration so previous test runs don't muck with this.
    monkeypatch.setattr('kordesii.registry._sources', {})

    decoder_dir = os.path.dirname(Sample_decoder)

    # Test registration
    assert not list(kordesii.iter_decoders('Sample'))
    kordesii.register_decoder_directory(decoder_dir, source_name='ACME')
    decoders = list(kordesii.iter_decoders('Sample'))
    assert len(decoders) == 1

    # Test it was registered properly
    decoder = decoders[0]
    assert decoder.name == 'Sample'
    assert decoder.source.name == 'ACME'
    assert decoder.source.path == decoder_dir

    # Test we can also pull by source name.
    decoders = list(kordesii.iter_decoders(source='ACME'))
    assert len(decoders) == 1
    decoders = list(kordesii.iter_decoders('ACME:'))
    assert len(decoders) == 1


def test_iter_decoders(monkeypatch, Sample_decoder):
    monkeypatch.setattr('kordesii.registry._sources', {})

    source = os.path.abspath(os.path.dirname(Sample_decoder))
    kordesii.register_decoder_directory(source)

    decoders = list(kordesii.iter_decoders('Sample'))
    assert len(decoders) == 1

    decoder = decoders[0]
    assert isinstance(decoder, Decoder)
    assert decoder.name == 'Sample'

    decoders = list(kordesii.iter_decoders(source=source))
    assert len(decoders) == 1

    decoder = decoders[0]
    assert isinstance(decoder, Decoder)
    assert decoder.name == 'Sample'

    assert list(kordesii.iter_decoders(name='bogus')) == []
    assert list(kordesii.iter_decoders(source='bogus')) == []
