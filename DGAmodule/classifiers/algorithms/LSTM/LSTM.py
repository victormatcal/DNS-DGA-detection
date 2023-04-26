#!/usr/bin/ python
""" This is a module to interact with Twitter API using python functions.

It provides functions to gather tweets searching them by keywords and
hashstags, among other things, on Twitter API in a simple way.
"""

import pathlib
import logging
import logging.config
import random

import numpy
from keras_preprocessing.sequence import pad_sequences
from keras.models import Sequential, load_model
from keras.layers import Dense, LSTM
from keract import get_activations, display_activations

from ..algorithm import Algorithm

# fix random seed for reproducibility
numpy.random.seed(1234)

class LSTM(Algorithm):

    def __init__(self):
        # Default params:
        # Dictionary
        charset = list("abcdefghijklmnopqrstuvwxyz0123456789.-")
        self.dictionary = dict(zip(charset, range(len(charset))))

        # Model
        path = str(pathlib.Path(__file__).parent.absolute())
        model_file = path + "/models/model-proposed.h5" # 50 neurons + 10 batch + softsign
        self.model = load_model(model_file)

    def update_dictionary(self, charset):
        self.dictionary = dict(zip(charset, range(len(charset))))

    def update_model(self, model_file):
        update_model = load_model(model_file)
        self.model = update_model

    def predict(self, domain: str) -> bool:
        novalue = [float(0)] * len(self.dictionary)

        domainX, domainY = _domainlist_to_dataset([domain, 67*"x"], 0, self.dictionary)
        domainP = pad_sequences(domainX, dtype=float, value=novalue, padding='post')
        domainF = numpy.array(domainP, dtype=float)

        score = numpy.asarray(self.model.predict(domainF))
        aRes = numpy.where(score[0] >= 0.5, True, False)

        return bool(aRes)

    def __str__(self) -> str:
        return "LSTM"


# Translate Domain Name to Vector
def _domain_to_vector(domain, dictionary):
    res = []
    for c in list(domain):
        v = [float(0)] * len(dictionary)
        v[dictionary[c]] = 1.0
        res.append(v)
    return res

# Translate Domain List to DataSet format
def _domainlist_to_dataset(domainlist, result, dictionary):
    x = [ _domain_to_vector(v, dictionary) for v in domainlist ]
    y = [ [result] for y in range(len(x))]
    return x, y

