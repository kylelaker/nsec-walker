import json
import traceback
import sys

import click
import dns.name

from nsecwalker import error, query

_FORMATTERS = {}


def formatter(name):
    def decorator(func):
        _FORMATTERS[name] = func
        return func

    return decorator


@formatter("text")
def plain_text_formatter(names):
    return "\n".join(names)


@formatter("json")
def json_formatter(names):
    return json.dumps(names, indent=2, default=str)


def walk(name):
    dns_name = dns.name.from_unicode(name)
    names = [dns_name]
    nameset = {dns_name}
    while True:
        try:
            result = query.query(names[-1])
            if not result:
                break
            if result in nameset:
                raise error.CycleDetectedError(result)
            # A list allows preserving order while a set allows a quick
            # lookup based on the name
            names.append(result)
            nameset.add(result)
        # Attempt to preserve whatever records were able to be found
        # by breaking from the loop on a resolution error or Ctrl-C;
        # hopefully the write happens quick enough that it's not an
        # issue.
        except error.ResolutionError as resolve_err:
            click.echo(resolve_err, err=True)
            click.echo("".join(traceback.format_exception(resolve_err)), err=True)
            break
        except KeyboardInterrupt:
            break
    return names


@click.command("nsec-walker")
@click.argument("name")
@click.option(
    "--output",
    type=click.Choice(_FORMATTERS.keys()),
    default="json",
    help="The format to output the names in",
)
def main(name, output):
    names = walk(name)
    click.echo(_FORMATTERS[output](names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
