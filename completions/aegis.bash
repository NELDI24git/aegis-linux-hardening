_aegis_completion() {
  local cur prev commands profiles
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="audit list-checks list-fixes profiles doctor inventory baseline policy integrity plan preflight fix transactions rollback"
  profiles="general web-server database bastion container-host minimal"
  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
  elif [[ "$prev" == "--profile" ]]; then
    COMPREPLY=( $(compgen -W "$profiles" -- "$cur") )
  fi
}
complete -F _aegis_completion aegis
