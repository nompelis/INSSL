# INSSL

A straight-forward tutorial on using the Secure Socket Layer (SSL).
An intuitive interface for using OpenSSL that does not make one nauseous.
A program to make web queries over HTTPS using CA-verified certificates.
A skeletal SSL server-client program over which one can build applications.


SUMMARY

1. Use this code if you want to learn how SSL works and how you are expected
to use it.

2. Use this code to learn how to make HTTPS queries with elementary CA
certificate validation.

3. Use this code to learn how to create a client-server framework/application
that uses secure TCP sockets by creating an SSL layer over TCP connections
using the OpenSSL library's API.

4. Use the comments in this code to understand what the OpenSSL programmers
neglected to add to their manual pages, tutorials and documentation.

5. This software is at least as terrible as all the tutorials I had to
read/study in order to write it. Thanks go to all those people who took the
time to share their experience and understanding of the OpenSSL library over
various weblogs and tutorial pages. I certainly would have not been able to
put this together by reading manual pages.


USING THIS CODE

- Compiling

Look in the Makefile. Do whatever it takes to compile it without warnings
so that you can be a happy user. On Linux, with the GNU compiler (gcc), and
with the OpenSSL libraries that came with my Slackware distribution, as well
as on a handful of SuSE installations and OpenBSD, this worked fine for me.

You will find that if your system's OS is old or shipped with an older version
of OpenSSL, and therefore it has deprecated symbols (functions/constants),
you will have compiler errors and caution warnings -- rightfully so. In the
Makefile there is a variable that allows one to set a shell variable for where
their prefered OpenSSL version is installed, and it can be used. Remove this
if your system's OpenSSL version is a good one and you do not want to have
to set that variable, etc.

- Running

There are two modes of execution at present: a client and a server mode.
This is so that one can build a single executable very quickly and play from
a couple of different terminals. The software needs a private key file and
the corresponding certificate file, which can be extracted from the key.
This can be done with the "openssl" command that ships with the OpenSSL
library. The sequence of commands should is discussed here, as well as the
rationale behind them.

Create a self-signed certificate, which will be eventually stored in the file
"cert.pem" in the directory where several commands will be executed. This
certificate will be served to the clients by the server. There are two choices
for using this certificate: (a) verify it against a certificate authority (CA)
and have the client confirm that they are talking to the server they expect,
and (b) having this certificate embedded in the client, verify that the server
is the one the client expects. The first scenario is for when the client has
no affiliation to the server; say, the client is a web-browser and the server
is a web-server far far away. In that case, the client takes the certificate
and verifies that it has been signed by a certificate authority, such that a
third party vouches for the identity of the server. This scenario will fail
in our implementation because the certificate will be self-signed, as discussed
previously. The second scenario is good for verifying that there is no
malicious server to which the client is talking. The idea is that the maker
of the software (that is "us'), embeds the certificate in the client software
first. Then, when the client connects to the server and gets its certificate,
it can verify the contents, such as serial number and other stuff. On success,
the client knows that it is... talking to the mothership, say.

To create a certificate, we need a private key, which is to be safeguarded on
the server side. We do this with a command like this:

     openssl genpkey -algorithm RSA -out key.pem -outform PEM \
                     -pkeyopt rsa_keygen_bits:2048

This command tells the OpenSSL framework front-end to create a private key
that is written in the PEM format; there is a choice made for the number of
bits used and the algorithm employed. The PEM format is what is called a
"Base64-encoded" chunk of binary data. When converted to binary, it is a very
specific type of format that contains all the key information that is to remain
secure and private. (The OpenSSL library has API calls that help you deal with
the key once it is loaded, but we only load it from a PEM file, so all of this
is done for you by OpenSSL after you have the "key.pem" file in hand.)

The next step involves creating a "certificate request" which is to say you
would like a certificate authority to sign your certificate and generate a
certificate for you. To do this, you provide the private key data and the
data that you would like to have embedded in the certificate. The command is
this:

    openssl req -new -key key.pem -out server.csr

This will create the "server.csr" file in the current working directory.

Use this certificate file and the private key to create a certificate. Because
the key used for the digital signing is your own, this is "self-signing." The
command is this:

    openssl x509 -req -in server.csr -signkey key.pem -out cert.pem

By trying the following two commands you can see the contents of the key and
the certificate, with all binary data printed in hex:

    openssl rsa -text -in key.pem
    openssl x509 -text -in cert.pem

The output for the key will only show the internal data, while the output for
the certificate will contain the issuer and signing information. If you have
got this far, the files "key.pem" and "cert.pem" are ready for use.

Execute the server by simply executing the program:

    ./a.out

Execute the client by executing the program with arguments:

    ./a.out localhost 60001

The port number "60001" is hard-wired inside the code. You will see that the
client will make three connections to the server, a message will be exchanged,
and both server and client will terminate.

- Studying

You want to follow closely what the software does by keeping the high
verbosity switches and adding some output of your own.


MOTIVATION

Nothing needs to be said about this... If you are actually reading this, you
have shared my and several other persons' frustration, and now you are ready
to take matters into your own hands to learn SSL with OpenSSL. You may also
want to build software that, say...

- makes license queries to your servers
- sends user-data and other "statistics" to your server
- verifies that it is talking _only_ to its peers (clients)
- scrapes data off the web through HTTPS
- ... (use your imagination)


LICENSE

You agree to all these terms and conditions:

/******************************************************************************

 Copyright (c) 2018-2021, Ioannis Nompelis

 All rights reserved.

 Redistribution and use in source and binary forms, with or without any
 modification, are permitted provided that the following conditions are met:
 1. Redistribution of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistribution in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the following acknowledgment:
    "This product includes software developed by Ioannis Nompelis."
 4. Neither the name of Ioannis Nompelis and his partners/affiliates nor the
    names of other contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.
 5. Redistribution or use of source code and binary forms for profit must
    have written permission of the copyright holder.
 
 THIS SOFTWARE IS PROVIDED BY IOANNIS NOMPELIS ''AS IS'' AND ANY
 EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL IOANNIS NOMPELIS BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 ******************************************************************************/


IN 2021/10/09

