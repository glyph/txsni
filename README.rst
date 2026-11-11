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

AI Policy
---------

txsni follows the `Twisted AI Policy <https://docs.twisted.org/en/latest/development/ai-policy.html>`_. This means this project does not allow the inclusion of the outputs of generative AI tools.
