
import os

from kordesii.decoder import Decoder


def test_metadata_extraction(Sample_decoder):
    decoder = Decoder(Sample_decoder)

    assert decoder.name == 'Sample'
    assert decoder.author == 'DC3'
    assert decoder.description == 'Sample decoder'
    assert decoder.source.name == os.path.dirname(Sample_decoder)
    assert decoder.source.path == os.path.dirname(Sample_decoder)
