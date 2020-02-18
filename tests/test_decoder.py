from kordesii.decoder import Decoder


def test_metadata_extraction(Sample_decoder):
    decoder = Decoder(str(Sample_decoder))

    assert decoder.name == "Sample"
    assert decoder.author == "DC3"
    assert decoder.description == "Sample decoder"
    assert decoder.source.name == Sample_decoder.dirname
    assert decoder.source.path == Sample_decoder.dirname
