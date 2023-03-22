# Formal verification of Autograph

This document describes the work being done to formally verify the Autograph
protocol.

## Verifpal

A [Verifpal](https://verifpal.com/) model is currently available in the
`./verifpal` folder.

> ⚠️ Please note that Verifpal is currently experimental software and that the
> accuracy of this model has not been verified by anyone other than the author.

If you want to run the attacker analysis of the model locally then please follow
the [instructions](https://verifpal.com/software) on the Verifpal website to
install the software.

Once the software is installed, clone this repository to your local machine and
run the attacker analysis by executing the following commands in a terminal
(replace `<path-to-repo>` with your local path to this repository):

```bash
cd <path-to-repo>/verification/verifpal
verifpal verify handshake.vp
```
