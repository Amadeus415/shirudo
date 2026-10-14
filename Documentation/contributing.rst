.. SPDX-License-Identifier: BSD-2-Clause
.. Copyright (c) 2026 Authors of shirudo

==============
Contributing
==============

shirudo follows the Linux kernel's development conventions for commits:
the coding style in :doc:`coding-style`, a kernel-style commit message,
a mandatory ``Signed-off-by:`` line, and the same set of attribution
tags. This page states the parts of that process that apply here; the
kernel's ``Documentation/process/submitting-patches.rst`` is the
reference for anything not covered.

Commit messages
===============

The subject line is ``area: imperative summary`` in at most about 70
characters, where ``area`` names the part of the tree being changed
(``bpm:``, ``packaging:``, ``docs:``, ``tree:``, ``build:`` and so on).
The body, wrapped at 75 columns, explains why the change is made and
what it does, in that order; it is the permanent record read by
reviewers and by whoever bisects to the commit later. Describe the
user-visible behaviour, the invariant that motivated it and anything
that was tried and rejected. The body never contains emojis.

Sign your work
==============

Every commit carries a ``Signed-off-by:`` line, with no exception. The
sign-off certifies the Developer's Certificate of Origin, reproduced
here from the kernel's ``submitting-patches.rst``::

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

If you can certify that, add::

    Signed-off-by: Random J Developer <random@developer.example.org>

using a known identity; anonymous or pseudonymous sign-offs are not
accepted. ``git commit -s`` and ``git revert -s`` add the line for you.
A commit without a valid sign-off is not merged, and a maintainer who
applies a commit adds their own sign-off after the author's, so the
chain of ``Signed-off-by:`` lines records the real route the change
took. The first sign-off is the author's; the last is the person who
submits the commit.

Only a person can certify the DCO. Coding agents and other automated
tools must never add a ``Signed-off-by:`` line; the human who reviews
and submits the work signs it off and takes responsibility for it.

Tags
====

The tags below are used exactly as in the kernel. All of them go in
the trailer block together with the sign-offs, one per line.

``Co-developed-by:``
    Attributes co-authorship when several people worked on one commit.
    Every ``Co-developed-by:`` is immediately followed by the
    ``Signed-off-by:`` of that co-author, and the sign-offs keep the
    chronological order of the work; the submitter's sign-off is last::

        Co-developed-by: First Co-Author <first@example.org>
        Signed-off-by: First Co-Author <first@example.org>
        Signed-off-by: Submitting Author <author@example.org>

``Fixes:``
    Names the commit that introduced the bug being fixed, as the first
    twelve characters of its hash and its subject in parentheses::

        Fixes: 1234567890ab ("bpm: publish signed indexes from C")

    Use it on every bug fix whose origin is known; it is how the fix is
    traced back and how release branches decide what to pick up.

``Reported-by:``
    Credits the person who found and reported the bug. It is for bugs,
    not feature requests, and is followed by a ``Closes:`` tag with the
    URL of the report when one exists (``Link:`` when the commit fixes
    only part of what was reported).

``Suggested-by:``
    Credits the person whose idea the change implements.

``Tested-by:``
    Records that the named person tested the commit successfully in some
    environment. Say where when it matters, with a ``# suffix``::

        Tested-by: Alice Example <alice@example.org> # arm64, swtpm

``Reviewed-by:``
    States that the named person carried out a technical review and
    found the change acceptable, under the kernel's reviewer's
    statement of oversight. ``Acked-by:`` is the lighter form: approval
    from someone responsible for the affected area who did not review
    in that depth.

``Cc:``
    Lists people who had the chance to comment.

``Reported-by:``, ``Suggested-by:`` and ``Cc:`` may be added when the
person acted in public; every other tag needs that person's explicit
permission. When a later version of a change differs substantially, drop
the ``Tested-by:``, ``Reviewed-by:`` and ``Acked-by:`` tags it had
collected and say so in the cover text, so a tag never vouches for code
its author has not seen.

Before sending
==============

* Build both profiles and the helper (``make``, ``make shirudo-build``)
  and run ``make test-op``; run ``make test-tgt`` when the change
  touches target-side behaviour.
* Keep each commit to one logical change that builds and passes on its
  own, so the history bisects.
* Read :doc:`threat-model` before changing anything on a
  security-relevant path, and say in the commit message which invariant
  the change preserves or extends.
