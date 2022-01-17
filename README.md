# nsec-walker

Crudely walk the DNS `NSEC` records within a zone to enumerate all the existing
names. This does basic checking for cycles but performs no handling of
transient resolution failures. There's also not (currently) any sort of API;
however, the CLI will output the names as a JSON list by default.

## Getting Started

Clone the repository

    git clone https://github.com/kylelaker/nsec-walker && cd nsec-walker

And install the package (you may want to setup a virtualenv before this step)

    pip install -e .

And then run the script

    nsec-walker --help

Or

    nsec-walker DOMAIN

## License

This project is licensed under the terms of the MIT License. See
[LICENSE](LICENSE) for more information.