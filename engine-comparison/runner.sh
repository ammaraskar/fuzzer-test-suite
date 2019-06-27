#!/bin/bash
# Copyright 2017 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#
# Script to run on the runner VMs.  Executes several trials of a benchmark and
# uploads corpus snapshots for the dispatcher to pull.

. benchmark.cfg
. parameters.cfg
. fengine.cfg

# WAIT_PERIOD should be longer than the main loop, otherwise a sync cycle will
# be missed
readonly WAIT_PERIOD=20

# rsyncs directories recursively without deleting files at dst.
rsync_no_delete() {
  local src=$1
  local dst=$2
  gsutil -m rsync -rP "${src}" "${dst}"
}

same_dir_tree() {
  local dir1=$1
  local dir2=$2
  diff <(cd "${dir1}" && find . | sort) <(cd "${dir2}" && find . | sort)
}

# Exit status 0 if run limit or time limit has been exceeded
time_run_limits_exceeded() {
  if [[ "${MAX_TOTAL_TIME}" -gt 0 ]]; then
    [[ "${SECONDS}" -gt "${MAX_TOTAL_TIME}" ]] && return 0
  fi
  if [[ "${MAX_RUNS}" -gt 0 ]]; then
    local runs_finished="$(grep execs_done corpus/fuzzer_stats \
      | grep -o -E "[0-9]+")"
    [[ "${runs_finished}" -gt "${MAX_RUNS}" ]] && return 0
  fi
  return 1
}

conduct_experiment() {
  local exec_cmd=$1
  local trial_num=$2
  local bmark_fengine_dir=$3
  local next_sync=${WAIT_PERIOD}
  local cycle=1
  local sync_dir="${GSUTIL_BUCKET}/${EXPERIMENT}/experiment-folders"
  sync_dir="${sync_dir}/${bmark_fengine_dir}/trial-${trial_num}"

  rm -rf last-corpus corpus-archives results crashes
  mkdir -p last-corpus corpus-archives results crashes
  if [[ "$FUZZING_ENGINE" != "qsym" ]]; then
    rm -rf corpus
    mkdir -p corpus
  fi

  ${exec_cmd} > /tmp/fuzzer-log 2>&1 &
  local process_pid=$!
  SECONDS=0  # Builtin that automatically increments every second
  while kill -0 "${process_pid}"; do
    # Ensure that measurements happen every wait period
    local sleep_time=$((next_sync - SECONDS))
    sleep ${sleep_time}

    # qsym runs slave afl nodes, copy their outputs out
    if [[ "$FUZZING_ENGINE" == "qsym" ]]; then
      rm -rf corpus/crashes
      rm -rf corpus/hangs
      rm -rf corpus/queue
      ls corpus/afl-master/
      cp -r corpus/afl-master/crashes corpus/ || true
      cp -r corpus/afl-master/hangs corpus/ || true
      cp -r corpus/afl-master/queue corpus/ || true
      cp corpus/afl-master/fuzzer_stats corpus/ || true
    fi

    # Delete most crashes and logs to save disk space.
    find . -name "fuzz-[1-9][0-9]*.log" -delete
    if [[ -z "$(ls -A crashes)" ]]; then
      mv corpus/crashes/* corpus/hangs/* crashes/ || true
      mv crash-* leak* timeout* oom* crashes/ || true
      if [[ -n "$(ls -A crashes)" ]]; then
        cp fuzz-0.log crashes/* results/
        echo "${cycle}" >> results/first-crash-cycle
      fi
    else
      rm -rf crash-* leak* timeout* oom*
    fi

    # copy fuzzer logs
    cp /tmp/*-log results/ || true
    # copy individual fuzz logs if they exist
    mkdir -p results/all-fuzz-logs/
    cp ./fuzz-*.log results/all-fuzz-logs/ || true
    # copy qsym files if they exist
    cp -r /tmp/*/qsym-out-* results/all-fuzz-logs/ || true

    # Snapshot
    cp -r corpus corpus-copy

    if same_dir_tree corpus-copy last-corpus; then
      # Corpus is unchanged; avoid rsyncing it.
      echo "${cycle}" >> results/unchanged-cycles
    else
      tar -czf "corpus-archives/corpus-archive-${cycle}.tar.gz" corpus-copy
      rsync_no_delete corpus-archives "${sync_dir}/corpus"
    fi

    rsync_no_delete results "${sync_dir}/results"

    # Done with snapshot
    rm -r last-corpus
    mv corpus-copy last-corpus
    rm "corpus-archives/corpus-archive-${cycle}.tar.gz"

    time_run_limits_exceeded && kill -15 "${process_pid}"

    cycle=$((cycle + 1))
    next_sync=$((cycle * WAIT_PERIOD))
    # Skip cycle if need be
    while [[ ${next_sync} -lt ${SECONDS} ]]; do
      echo "${cycle}" >> results/skipped-cycles
      cycle=$((cycle + 1))
      next_sync=$((cycle * WAIT_PERIOD))
    done
  done

  # Sync final corpus
  tar -czf "corpus-archives/corpus-archive-${cycle}.tar.gz" corpus
  rsync_no_delete corpus-archives "${sync_dir}/corpus"

  # copy fuzzer logs
  cp /tmp/*-log results/ || true
  # copy individual fuzz logs if they exist
  mkdir -p results/all-fuzz-logs/
  cp ./fuzz-*.log results/all-fuzz-logs/ || true
  # copy qsym files if they exist
  cp -r /tmp/*/qsym-out-* results/all-fuzz-logs/ || true

  # Sync final fuzz log
  echo "${exec_cmd}" > command-line.txt
  mv fuzz-0.log command-line.txt crashes/* results/
  mv corpus/crashes corpus/hangs corpus/fuzzer_stats results/
  rsync_no_delete results "${sync_dir}/results"
}

main() {
  # This name used to be the name of the file fengine.cfg. It was renamed in the
  # dispatcher, so it was stored as metadata.
  local binary="./${BENCHMARK}-${FUZZING_ENGINE}"
  local metadata_url="http://metadata.google.internal/computeMetadata/v1"
  local fengine_url="${metadata_url}/instance/attributes/fengine"
  local fengine_name="$(curl "${fengine_url}" -H "Metadata-Flavor: Google")"
  local trial_url="${metadata_url}/instance/attributes/trial"
  local trial="$(curl "${trial_url}" -H "Metadata-Flavor: Google")"

  chmod 750 "${binary}"

  if [[ "${FUZZING_ENGINE}" == "afl" ]]; then
    chmod 750 afl-fuzz

    # AFL requires some starter input
    [[ ! -d seeds ]] && mkdir seeds
    [[ ! $(find seeds -type f) ]] && echo > ./seeds/nil_seed

    # AFL doesn't work with inputs >1MB.
    find seeds -size +1M -delete

    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export ASAN_OPTIONS="abort_on_error=1:symbolize=0"

    local exec_cmd="./afl-fuzz ${BINARY_RUNTIME_OPTIONS} -i seeds -o corpus"
    if ls ./*.dict; then
      local dict_path="$(find . -maxdepth 1 -name "*.dict" | head -n 1)"
      exec_cmd="${exec_cmd} -x ${dict_path}@9"
    fi
    exec_cmd="${exec_cmd} -m none -- ${binary}"
  elif [[ "${FUZZING_ENGINE}" == "libfuzzer" || \
    "${FUZZING_ENGINE}" == "fsanitize_fuzzer" ]]; then
    export ASAN_OPTIONS="symbolize=0"

    local exec_cmd="${binary} ${BINARY_RUNTIME_OPTIONS}"
    exec_cmd="${exec_cmd} -workers=${JOBS} -jobs=100000000 -runs=${MAX_RUNS}"
    exec_cmd="${exec_cmd} -max_total_time=${MAX_TOTAL_TIME}"
    if ls ./*.dict; then
      local dict_path="$(find . -maxdepth 1 -name "*.dict" | head -n 1)"
      exec_cmd="${exec_cmd} -dict=${dict_path}"
    fi
    exec_cmd="${exec_cmd} -print_final_stats=1 -close_fd_mask=3 corpus"
    [[ -d seeds ]] && exec_cmd="${exec_cmd} seeds"
  elif [[ "${FUZZING_ENGINE}" == "qsym" ]]; then
    chmod 750 afl-fuzz
    chmod 750 afl-showmap
    chmod 750 ${binary/qsym/afl}

    echo "blank file" > fuzz-0.log
    mkdir -p corpus

    # AFL requires some starter input
    [[ ! -d seeds ]] && mkdir seeds
    [[ ! $(find seeds -type f) ]] && echo > ./seeds/nil_seed

    # AFL doesn't work with inputs >1MB.
    find seeds -size +1M -delete

    # Some kernel settings for qsym and AFL
    echo 0 | tee /proc/sys/kernel/yama/ptrace_scope
    echo core | tee /proc/sys/kernel/core_pattern

    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export ASAN_OPTIONS="abort_on_error=1:symbolize=0"

    local afl_cmd="./afl-fuzz -M afl-master ${BINARY_RUNTIME_OPTIONS} -i seeds -o corpus"
    local afl_slave_cmd="./afl-fuzz -S afl-slave ${BINARY_RUNTIME_OPTIONS} -i seeds -o corpus"
    if ls ./*.dict; then
      local dict_path="$(find . -maxdepth 1 -name "*.dict" | head -n 1)"
      afl_cmd="${afl_cmd} -x ${dict_path}@9"
      afl_slave_cmd="${afl_slave_cmd} -x ${dict_path}@9"
    fi
    afl_cmd="${afl_cmd} -m none -- ${binary/qsym/afl}"
    afl_slave_cmd="${afl_slave_cmd} -m none -- ${binary/qsym/afl}"

    # Run a master AFL in the background
    ${afl_cmd} > /tmp/afl-master-log 2>&1 &
    ${afl_slave_cmd} > /tmp/afl-slave-log 2>&1 &
    # let afl master kick in
    sleep 10

    local exec_cmd="/workdir/qsym/bin/run_qsym_afl.py -a afl-slave -o corpus -n qsym -- ${binary} @@"
  else
    echo "Error: Unsupported fuzzing engine ${FUZZING_ENGINE}"
    exit 1
  fi

  local bmark_fengine_dir="${BENCHMARK}-${fengine_name}"
  conduct_experiment "${exec_cmd}" "${trial}" "${bmark_fengine_dir}"

  # Delete this runner to save resources.
  gcloud compute instances delete --zone="${CLOUDSDK_COMPUTE_ZONE}" -q \
    "${INSTANCE_NAME}"
}

main "$@"
