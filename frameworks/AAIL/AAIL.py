import json

import constants as _C
from frameworks.Framework import Framework


class AAIL(Framework):
    """
    AWS Well-Architected Framework — Agentic AI Lens (AAIL).

    The lens maps lens-defined best practice IDs (AGENT<PILLAR>NN.BPNN) to
    Service Screener checks. Compliance evaluation follows the base Framework
    logic in frameworks/Framework.py.
    """

    def __init__(self, data):
        super().__init__(data)
