import json
import traceback
import sys

import click
import dns.name

from nsecwalker import error, query

ROOT_NAME = dns.name.from_text(".")

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


def walk(name: str):
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
            # There's not a ton of value in starting to chase NSEC records
            # across the entire DNS space (though there is an NSEC at .).
            # We should consider it the end of the zone. But by adding it
            # to the list of names first, we avoid returning a message that
            # there weren't any NSEC records (because there was one). Usually
            # this is just an intentional mitigation against walking the zone.
            if result == ROOT_NAME:
                break

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

    # Exit with a non-zero status code if there's only one name (or fewer)
    # in the resulting list. This indicates that there was not an NSEC record
    # present and that there was nothing to find. The `names` list will contain
    # the name that was given as input (though likely canonicalized)
    if len(names) <= 1:
        click.echo(f"No NSEC records found for {name}", file=sys.stderr)
        # This is the best way to set the return code because click doesn't
        # care about the function's return value
        sys.exit(1)

    click.echo(_FORMATTERS[output](names))


if __name__ == "__main__":
    sys.exit(main())
