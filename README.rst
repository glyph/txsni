txsni
=====

.. image:: https://travis-ci.org/glyph/txsni.svg?branch=master
    :target: https://travis-ci.org/glyph/txsni

Simple support for running a TLS server with Twisted.

Use it like this:

.. code-block:: console

   $ mkdir certificates
   $ cat private-stuff/mydomain.key.pem >> certificates/mydomain.example.com.pem
   $ cat public-stuff/mydomain.crt.pem >> certificates/mydomain.example.com.pem
   $ cat public-stuff/my-certificate-authority-chain.crt.pem >> \
       certificates/mydomain.example.com.pem
   $ twist web --port txsni:certificates:tcp:443

Enjoy!

