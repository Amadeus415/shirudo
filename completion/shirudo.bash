# bash completion for shirudo                              -*- shell-script -*-
#
# Command and subcommand name lists are pulled live from the binary via
# `shirudo <command> --list-cmds`, so adding a (sub)command in the
# C dispatch table makes it appear here automatically -- this file does
# NOT need editing for new names. Per-command FLAG lists are still
# hand-maintained below; update them when a flag is added or removed.
#
# Install: copied to $(sharedir)/bash-completion/completions/shirudo by
# `make install`. To try it in place: `source completion/shirudo.bash`.

_shirudo()
{
	local cur cword cmd sub bin
	cur="${COMP_WORDS[COMP_CWORD]}"
	cword=$COMP_CWORD
	bin="${COMP_WORDS[0]}"

	# First word: the top-level command, pulled live from the binary
	# the user is completing -- always matches that build.
	if (( cword == 1 )); then
		local cmds
		cmds=$("$bin" --list-cmds 2>/dev/null)
		COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
		return
	fi

	cmd="${COMP_WORDS[1]}"
	sub="${COMP_WORDS[2]}"
	case "$cmd" in
	upatch)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" upatch --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $cur == -* ]]; then
			case "$sub" in
			load|unload)
				COMPREPLY=( $(compgen -W "--expect-chain= \
					--expect-version-id= --no-precheck \
					--no-version-check --report=" \
					-- "$cur") )
				;;
			info|list)
				COMPREPLY=( $(compgen -W "--json" -- "$cur") )
				;;
			get)
				# no flags beyond --help
				COMPREPLY=()
				;;
			esac
		else
			COMPREPLY=( $(compgen -f -X '!*.upatch' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	remote)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" remote --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $sub == label && cword -eq 3 ]]; then
			local subs
			subs=$("$bin" remote label --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs" -- "$cur") )
		elif [[ $cur == -* ]]; then
			case "$sub" in
			add)
				COMPREPLY=( $(compgen -W "--label" -- "$cur") )
				;;
			list)
				COMPREPLY=( $(compgen -W "--json \
					--filter= --selector=" -- "$cur") )
				;;
			label)
				COMPREPLY=( $(compgen -W "--filter= \
					--selector=" -- "$cur") )
				;;
			esac
		fi
		;;
	build)
		if [[ $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "-o --name --key --cert \
				--vmlinux --extra-cflags --unload \
				--payload-sha256" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -X '!*.bpf.c' -- "$cur") \
				    $(compgen -f -X '!*.bpf.o' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	rollout)
		if [[ $cur == -* ]]; then
			COMPREPLY=( $(compgen -W "--expect-chain= \
				--expect-version-id= --report= --filter= \
				--selector= --no-precheck --no-version-check \
				--dry-run --sudo" -- "$cur") )
		else
			COMPREPLY=( $(compgen -f -X '!*.upatch' -- "$cur") \
				    $(compgen -d -- "$cur") )
		fi
		;;
	nodes)
		if (( cword == 2 )); then
			local subs
			subs=$("$bin" nodes --list-cmds 2>/dev/null)
			COMPREPLY=( $(compgen -W "$subs --json --filter= \
				--selector=" -- "$cur") )
		elif [[ $sub == show ]]; then
			COMPREPLY=( $(compgen -W "--json --show-full upatches" \
				-- "$cur") )
		else
			COMPREPLY=( $(compgen -W "--json --filter= \
				--selector=" -- "$cur") )
		fi
		;;
	init)
		COMPREPLY=( $(compgen -W "--check-only --no-tpm" -- "$cur") )
		;;
	status)
		COMPREPLY=( $(compgen -W "--json --include-tpm \
			--include-system --include-eventlog \
			--include-kernellog --include-modules \
			--include-maps --show-full" -- "$cur") )
		;;
	keys)
		COMPREPLY=( $(compgen -W "--keys-dir=" -- "$cur") )
		;;
	genkey)
		COMPREPLY=( $(compgen -W "--keys-dir= --force -f" -- "$cur") )
		;;
	config|version|help)
		# nothing to complete beyond --help / --list-cmds
		;;
	esac

	# A "--flag=" completion takes a value -- don't append a space.
	if (( ${#COMPREPLY[@]} == 1 )) && [[ ${COMPREPLY[0]} == *= ]]; then
		compopt -o nospace 2>/dev/null
	fi
}
complete -F _shirudo shirudo
