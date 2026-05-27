# bash completion for shirudo                              -*- shell-script -*-
#
# The top-level command list is pulled live from
# `shirudo help --list-cmds`, so a command added to the dispatch table in
# shirudo.c appears here automatically -- this file does NOT need editing
# for new top-level commands. The per-command subcommand and flag lists
# below are hand-maintained; update them only when a subcommand or flag
# is added.
#
# Install: copied to $(sharedir)/bash-completion/completions/shirudo by
# `make install`. To try it in place: `source completion/shirudo.bash`.

_shirudo()
{
	local cur cword cmd
	cur="${COMP_WORDS[COMP_CWORD]}"
	cword=$COMP_CWORD

	# First word: the command -- queried live from the binary the user
	# is completing (${COMP_WORDS[0]}), so it always matches that build.
	if (( cword == 1 )); then
		local cmds
		cmds=$("${COMP_WORDS[0]}" help --list-cmds 2>/dev/null)
		COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
		return
	fi

	cmd="${COMP_WORDS[1]}"
	case "$cmd" in
	upatch)
		if (( cword == 2 )); then
			COMPREPLY=( $(compgen -W "info load unload list get" -- "$cur") )
		elif [[ $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--expect-chain= --expect-version-id= --report= --no-precheck --no-version-check --json" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -X '!*.upatch' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	remote)
		(( cword == 2 )) && \
			COMPREPLY=( $(compgen -W "add list rm rename show" -- "$cur") )
		;;
	build)
		if [[ $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "-o --name --key --cert --vmlinux \
				--extra-cflags --unload --payload-sha256" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -X '!*.bpf.c' -- "$cur") \
				    $(compgen -f -X '!*.bpf.o' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	rollout)
		if [[ $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--expect-chain= --expect-version-id= \
				--report= --selector= --no-precheck --no-version-check \
				--dry-run --sudo" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -X '!*.upatch' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	nodes)
		if [[ ${COMP_WORDS[2]} == show ]]; then
			COMPREPLY=( $(compgen -W "--json" -- "$cur") )
		else
			COMPREPLY=( $(compgen -W "show --json --filter= \
				--selector=" -- "$cur") )
		fi
		;;
	init)
		COMPREPLY=( $(compgen -W "--check-only --no-tpm" -- "$cur") )
		;;
	status)
		COMPREPLY=( $(compgen -W "--json --include-tpm" -- "$cur") )
		;;
	esac

	# A "--flag=" completion takes a value -- don't append a space.
	if (( ${#COMPREPLY[@]} == 1 )) && [[ ${COMPREPLY[0]} == *= ]]; then
		compopt -o nospace 2>/dev/null
	fi
}
complete -F _shirudo shirudo
