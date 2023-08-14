#!/usr/bin/ python
""" This is a module to interact with Twitter API using python functions.

It provides functions to gather tweets searching them by keywords and
hashstags, among other things, on Twitter API in a simple way.
"""

import pathlib
import logging
import logging.config
import random

from ngram import NGram
import itertools
import collections
import statistics
import numpy as np
import pandas as pd
import datetime
# import warnings
# warnings.filterwarnings('ignore')
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

from ..algorithm import Algorithm

# fix random seed for reproducibility
np.random.seed(1234)

class RandomForest(Algorithm):

    def __init__(self):
        # Default params:

        # Model
        path = str(pathlib.Path(__file__).parent.absolute())
        model_file = path + "/models/model-proposed.sav" #0.9017
        self.model = pickle.load(open(model_file, 'rb'))

    def update_model(self, model_file):
        update_model = pickle.load(open(model_file, 'rb'))
        self.model = update_model

    def predict(self, domain: str) -> bool:
        domain_p = _prepare_domain(domain).reshape(1, -1)
        result= self.model.predict(domain_p)

        return result[0] == 'MALWARE'

    def train(self):
        raw_data_clean = pd.read_csv('./data/clean.csv', header=None, sep=",", na_values="NaN", decimal=",", encoding='latin-1')
        raw_data_dga = pd.read_csv('./data/dga.csv', header=None, sep=",", na_values="NaN", decimal=",", encoding='latin-1')

        frames = [raw_data_clean, raw_data_dga]

        raw_data = pd.concat(frames)

        raw_data2 = raw_data.iloc[:,3:18]

        X = raw_data2.values # Input features (attributes)
        y = raw_data.iloc[:,2].values # Target vector

        X_train, X_test, y_train, y_test = train_test_split(X, y, train_size = 0.8, test_size=0.2, random_state=0)

        rf = RandomForestClassifier(n_estimators=400, criterion='gini')
        rf.fit(X_train, y_train)
        prediction_test = rf.predict(X=X_test)

        # source: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html

        # Accuracy on Test
        print("Training Accuracy is: ", rf.score(X_train, y_train))
        # Accuracy on Train
        print("Testing Accuracy is: ", rf.score(X_test, y_test))

        filename = path + "/models/model-proposed.sav"
        pickle.dump(rf, open(filename, 'wb'))


    def __str__(self) -> str:
        return "Random Forest"


def _ngram_stats( vector ):
  counter=collections.Counter(vector)
  vector_values = counter.values()
  m = statistics.mean(vector_values)
  v = statistics.variance(vector_values)
  s = statistics.stdev(vector_values)
  return [m, v, s]

def _multi_replace( source, chars_out, char_in ):
  for c in chars_out:
    source = source.replace(c, char_in)
  return source

def _prepare_domain(domain_name, tag="Unknown"):

    feature = []

    aux1_domain_name = _multi_replace( domain_name, ['b', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z'], "c" )
    aux2_domain_name = _multi_replace( aux1_domain_name, ['a', 'e', 'i', 'o', 'u'], "v" )
    aux3_domain_name = _multi_replace( aux2_domain_name, ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'], "n" )
    masked_domain_name = _multi_replace( aux3_domain_name, ['-'], "s" )

    #feature.append(domain_name)
    #feature.append(masked_domain_name)
    #feature.append(tag)

    ### ID Designation
    # Features 1-3: 1-gram mean, variance and standard deviation
    n = NGram(N=1)
    v = list(n._split(domain_name))
    [f1, f2, f3] = _ngram_stats(v)
    feature.extend([f1, f2, f3])

    # Feature 4: 2-gram standard deviation
    n = NGram(N=2)
    v = list(n._split(domain_name))
    [f1, f2, f3] = _ngram_stats(v)
    feature.append(f3)

    # Feature 5: Number of different characters
    different_characters = len(set(list(domain_name)))
    feature.append( different_characters )

    # Feature 6: Domain name length
    domain_length = len(domain_name)
    feature.append( domain_length )

    # Feature 7-15: NGrams
    ngram_features = ["ccc", "cvc", "vcc", "vcv", "cv", "vc", "cc", "c", "v"]
    ngram_dict = {}
    for i in ngram_features:
        ngram_dict[i] = 0
    for i in [1, 2, 3]:
        ng = NGram(N=i)
        v = list(ng._split(masked_domain_name))
        for n in v:
            if n in ngram_features:
                ngram_dict[n] += 1
    feature.extend(ngram_dict.values())

    return np.array(feature, dtype=float)