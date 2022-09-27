

library("checkmate")

QUEUEKEY <- "queue"
SETQKEY <- "set.queue"
SETRKEY <- "set.running"
SETDKEY <- "set.dead"
JOBIDCOUNTER <- "jobscounter"
PAYLOADKEYPATTERN <- "payload.%s"
HEARTBEATKEYPATTERN <- "heartbeat.%s"
BATCHSIZE <- 256  # number of items to use in sscan etc.

HEARTBEATREFRESHINT <- 60
HEARTBEATLIFETIME <- 180


DEBUG <- get0("DEBUG", ifnotfound = FALSE)
DEBUG.jid <- NULL
DEBUG.identifier <- sprintf("%s:%s", system("hostname", intern = TRUE), Sys.getpid())

FUZZING <- get0("FUZZING", ifnotfound = FALSE)

if (FUZZING) {
  HEARTBEATREFRESHINT <- 1
  HEARTBEATLIFETIME <- 3
  BATCHSIZE <- 5
}

debugprint <- function(msg, ...) {
  if (DEBUG) {
    cat(paste0(format(Sys.time(), "%s | %F %H:%M:%OS3 %Z | "), DEBUG.identifier, " [", DEBUG.jid %??% "X", "] -- ", sprintf(msg, ...), "\n"))
  }
}

stopf <- function(msg, ...) {
  msg <- paste0(format(Sys.time(), "%s | %F %H:%M:%OS3 %Z | "), DEBUG.identifier, " [", DEBUG.jid %??% "X", "] -- ", sprintf(msg, ...))
  stop(simpleError(msg, sys.call(-1)))
}

print.REDIS <- function(x, ...) {
  cat(sprintf("<redis %s%s>\n", x$addr, if (is.null(x$socatpipe)) " (closed)" else ""))
}

close.REDIS <- function(con, ...) {
  if (!is.null(con$socatpipe)) {
    close(con$socatpipe)
    con$socatpipe <- NULL
  }
}

# return a redis connection
# pollrate: how often do we check whether socat call is still alive?
redis.initiate <- function(redisdir, pollrate = 0.1, env = NULL) {
  assertString(redisdir)
  redisdir <- normalizePath(redisdir)

  # the following because we use redisdir in the socat command line
  if (grepl(redisdir, "'|,")) stopf("redisdir may not contain \",\" or \"'\".")

  assertNumeric(pollrate, lower = 0)
  if (!dir.exists(redisdir)) stopf(sprintf("%s must be a directory.", redisdir))

  infofile <- file.path(redisdir, "instance.info")
  info <- readLines(infofile)

  addr <- assertString(info[[1]], pattern = "^[^:]+:[0-9]+$")
  password <- info[[2]]
  socketfile <- tempfile("clientsocket", tmpdir = redisdir, fileext = ".sock")
  certfile <- file.path(redisdir, "server.pem")
  cafile <- file.path(redisdir, "server.crt")
  socatcommand <- sprintf("socat 'unix-listen:%s,fork,reuseaddr' ssl:%s,cert=%s,cafile=%s,commonname=.", socketfile, addr, certfile, cafile)


  on.exit(close(socatpipe))

  # the following runs a small shell script and connects it to this R-process with a pipe. This is to make the command run in
  # background while also making sure it will get killed when this R-session unexpectedly gets killed.
  # The shell-script executes the 'socatcommand' in background (using '&'), and also executes 'read' in background (using '&').
  # The 'read' command does nothing until it receives a newline, or until 'socatpipe' is closed, either by close(socatpipe), or
  # because the R-process exited.
  # The script then waits until *either* of the background jobs terminates (using the 'wait -n' command). Whenever the script exits
  # (because of a signal or because of normal exiting: because either 'socatcommand' or 'read dummy' exited),
  # the 'pkill' command is run that kills all child-processes of this process.
  socatpipe <- pipe(sprintf(
    "/bin/bash -c 'trap \"exit 99\" INT TERM ; trap \"pkill -P $$\" EXIT ; %s & read dummy & wait -n'", socatcommand),
  "w")

  while (!file.exists(socketfile)) {
    Sys.sleep(pollrate)
    # we want to check whether the 'socatpipe'-command has failed.
    # We *hope* that pipe()-calls are executed in the correct order...
    # We 'pgrep' for a process that has the (unique) clientsocket tempfile in its command line
    # and is also a child process. The first could be spoofed by another user, but not the
    # second.
    procsfound <- readLines(tmp <- pipe(sprintf("pgrep -P %s -f %s", Sys.getpid(), basename(socketfile))))
    close(tmp)
    if (length(procsfound) != 1) stopf("Found %s socat background processes, probably the socat call had an error.", length(procsfound))
  }

  env <- env %??% new.env(parent = topenv())  # I'm not sure if 'topenv()' in function header would give smth wrong, so I'm careful...
  env$addr <- addr
  env$password <- password
  env$socatpipe <- socatpipe
  env$socketfile <- socketfile
  env$redisdir <- redisdir
  finalizer <- function(obj) {
    if (!is.null(obj$socatpipe)) {
      try(close(obj$socatpipe))
      obj$socatpipe <- NULL
    }
  }

  environment(finalizer) <- env
  reg.finalizer(env, finalizer, onexit = TRUE)
  class(env) <- "REDIS"
  on.exit()
  env
}

# make sure 'command' is trusted, otherwise shell injection!
# 'payload' may be missing, otherwise it is the last argument of 'command'
redis.execute <- function(connection, command, payload, deserialize.result = FALSE, on.empty = NULL) {
  assertClass(connection, "REDIS")
  if (is.null(connection$socatpipe)) {
    warning("connection is closed, reopening...")
    connection <- redis.initiate(connection$redisdir, env = connection)
  }
  assertCharacter(command, min.len = 1)

  on.exit({
    unlink(inputfile)
    unlink(resultfile)
  })

  inputfile <- tempfile("rediscall", fileext = ".in")
  resultfile <- gsub("\\.in$", ".out", inputfile)

  if (missing(payload)) {
    stdin <- ""
  } else {
    saveRDS(payload, inputfile, compress = FALSE, ascii = TRUE)
    stdin <- inputfile
  }

  if (FUZZING) {
    if (runif(1) < .005) {
      debugprint("FUZZING: redis.execute is randomly sabotaging connection")
      close(connection)
    }
    if (runif(1) < .1) {
      debugprint("FUZZING: redis.execute WAIT: 0.2s")
      Sys.sleep(0.2)
    } else if (runif(1) < .05) {
      debugprint("FUZZING: redis.execute WAIT: 2s")
      Sys.sleep(2)
    } else if (runif(1) < .01) {
      debugprint("FUZZING: redis.execute WAIT: 4s")
      Sys.sleep(4)
    } else if (runif(1) < .001) {
      debugprint("FUZZING: redis.execute randomly dying.")
      stopf("FUZZING KILL")
    }
  }

  for (retries in seq_len(3)) {

    returncode <- system2("redis-cli",
      c("-s", connection$socketfile,
        "--raw",
        if (!missing(payload)) "-x",
        shQuote(command)
      ), stdout = resultfile, stdin = stdin,
      env = paste0("REDISCLI_AUTH=", connection$password)
    )
    if (!returncode) break
    close(connection)
    connection <- redis.initiate(connection$redisdir, env = connection)
    if (retries == 2) Sys.sleep(1)
    (if (retries == 3) stopf else warning)(sprintf("redis-cli returned status %s on try %s", returncode, retries))
  }

  if (deserialize.result) {
    tryCatch(readRDS(resultfile), error = function(e) {
      if (identical(readBin(resultfile, "raw", 2), as.raw(0x0a))) {
        on.empty
      } else {
        stop(e)
      }
    })
  } else {
    readLines(resultfile)
  }
}

# run redis command, expect a single string as result
redis.execute.str <- function(connection, command, payload) {
  response <- redis.execute(connection, command, payload)
  if (testString(response)) return(response)
  debugprint("redis.execute.str got bad response:\n%s", paste(capture.output(print(response)), collapse = "\n"))
  (assertString(response))
}



submitJob <- function(connection, payload, payloadlifetime = HEARTBEATLIFETIME) {

  DEBUG.jid <<- NULL
  on.exit(DEBUG.jid <<- NULL)

  RETRIES <- 10
  RETRYBACKOFF <- sqrt(2)



  for (retry in seq_len(RETRIES)) {
    debugprint("Creating job id")
    jobid <- redis.execute.str(connection, c("INCR", JOBIDCOUNTER))
    DEBUG.jid <<- jobid
    debugprint("Job id: %s", jobid)

    payloadkey <- sprintf(PAYLOADKEYPATTERN, jobid)
    debugprint("Creating volatile payload key %s with timeout %.2f", payloadkey, round(payloadlifetime))
    result <- redis.execute.str(connection, c("SET", payloadkey, jobid, "EX", round(payloadlifetime)))  # if we could pipe binary directly, I would do this here...
    if (result != "OK") stopf("Creating payload key failed")

    debugprint("Adding %s to 'queued' set", jobid)
    result <- redis.execute.str(connection, c("SADD", SETQKEY, jobid))
    if (result != "1") stopf("Adding job to 'queued' set failed")

    # enqueue
    debugprint("Enqueueing %s to stream", jobid)
    queueid <- redis.execute.str(connection, c("XADD", QUEUEKEY, "*", "JOBID", jobid, "PAYLOAD"), payload)
    debugprint("Job %s has queue id %s", jobid, queueid)

    debugprint("Checking if %s is still there", payloadkey)
    if (redis.execute.str(connection, c("PERSIST", payloadkey)) == "1") {
      # payload has not been removed yet, so we were definitely successful
      debugprint("%s made persistent, job %s is submitted", payloadkey, jobid)
      return(jobid)
    }

    debugprint("Removing %s from 'queued' set (if still there)", jobid)
    result <- redis.execute.str(connection, c("SREM", SETQKEY, jobid))
    debugprint("Result: %s", result)

    debugprint("Removing %s from queue stream", queueid)
    result <- redis.execute.str(connection, c("XDEL", QUEUEKEY, queueid))
    debugprint("Result: %s", result)

    for (tryset in c(SETRKEY, SETDKEY)) {
      still.exists <- redis.execute.str(connection, c("SISMEMBER", tryset, jobid)) == "1"
      if (still.exists) {
        debugprint("Job %s still exists in '%s' set, therefore assuming we were successful", jobid, tryset)
        return(jobid)
      }
    }
    debugprint("Failed to create job %s; trying again with more timeout.", jobid)
    payloadlifetime <- payloadlifetime * RETRYBACKOFF
  }
  stopf("%s Failed to create job after %s tries.", DEBUG.identifier, RETRIES)
}

killJob <- function(connection, jobid) {
  DEBUG.jid <<- jobid
  on.exit(DEBUG.jid <<- NULL)

  assertString(jobid, min.chars = 1)
  debugprint("Trying to kill job: %s", jobid)
  for (tryset in c(SETQKEY, SETRKEY)) {
    debugprint("Removing job %s from set %s, if present", jobid, tryset)
    result <- redis.execute.str(connection, c("SMOVE", tryset, SETDKEY, jobid))
    debugprint("Result: %s", result)
  }

  for (toremove in sprintf(c(PAYLOADKEYPATTERN, HEARTBEATKEYPATTERN), jobid)) {
    debugprint("Removing key %s, if exists", toremove)
    result <- redis.execute.str(connection, c("UNLINK", toremove))
    debugprint("Result: %s", result)
  }
  debugprint("Done. Rest in Peace, %s!", jobid)
}


# check.payload.fn: payload -> logical(1) ("is job acceptable?")
# job.initfun: payload -> jobhandle
# job.evalfun: (jobhandle, timeout) -> logical(1) ("is job still alive?")
# job.killfun: jobhandle
worker <- function(connection, check.payload.fn, job.initfun, job.evalfun, job.killfun, heartbeatlife = HEARTBEATLIFETIME, heartbeatrefresh = HEARTBEATREFRESHINT) {
  DEBUG.jid <<- NULL
  on.exit(DEBUG.jid <<- NULL)

  curindex <- "0"  # index at which to start querying queue
  maxindex <- "0"
  # list of all candidates that could potentially be run if it turns out some other worker blocked heartbeat without actually running
  # we keep this list so that clean up jobs get executed eventually, even if some other worker crashes.
  debugprint("Getting client id")
  clientid <- redis.execute.str(connection, c("CLIENT", "ID"))
  debugprint("Client ID %s", clientid)
  candidate.queue <- list()
  repeat {
    DEBUG.jid <<- NULL
    # need to get last id that was seen by the stream, since there is a blocking bug in redis
    # https://stackoverflow.com/q/55497990
    if (curindex != "0") {
      # this fails when the stream key does not exist, so we only do this after XREAD already returned an ID.
      debugprint("Getting queue stream max ID")
      maxindex <- redis.execute.str(connection, c("EVAL",
        "return redis.call('XINFO', 'STREAM', KEYS[1])[10]",
        "1", QUEUEKEY))
      debugprint("Result: %s", maxindex)
    }
    debugprint("Polling stream %s for at most %.3f seconds at position %s", QUEUEKEY, heartbeatrefresh, curindex)
    ## note that 'BLOCK' needs milliseconds!
    reply <- redis.execute(connection, c("XREAD", "COUNT", "1", "BLOCK", heartbeatrefresh * 1000, "STREAMS", QUEUEKEY, curindex))
    if (identical(reply, c(QUEUEKEY, ""))) {
      debugprint("redis XREAD Polling bug triggered. Setting curindex from %s to %s.", curindex, maxindex)
      curindex <- maxindex
    } else if (!identical(reply, "")) {
      # reply format: <STREAMNAME> <ID> <FIELD> <VALUE> [<FIELD> <VALUE>, ...]
      # (we ignore streamname and field names)
      # expected reply: c(QUEUEKEY, queueid, "JOBID", jobid, "PAYLOAD", <payload>)
      assertCharacter(reply, any.missing = FALSE, min.len = 6)
      DEBUG.jid <<- reply[[4]]

      curindex <- reply[[2]]
      jobinfo <- list(
        payload = unserialize(charToRaw(paste(reply[-(1:5)], collapse = "\n"))),
        queueid = reply[[2]],
        jobid = reply[[4]]
      )
      debugprint("Got reply: jobid %s, queueid %s.", jobinfo$jobid, jobinfo$queueid)
      if (FUZZING) {
        debugprint("FUZZING: Got payload (%s, %s).", jobinfo$payload[[1]], jobinfo$payload[[2]])
      }

      payloadkey <- sprintf(PAYLOADKEYPATTERN, jobinfo$jobid)
      debugprint("Checking if payload key %s exists", payloadkey)
      job.ok <- redis.execute.str(connection, c("EXISTS", payloadkey)) == "1"
      if (!job.ok) {
        debugprint("Payload key %s not found; removing job %s.\nFirst: removing %s from %s, if present", payloadkey, jobinfo$jobid, jobinfo$jobid, SETQKEY)
        result <- redis.execute.str(connection, c("SREM", SETQKEY, jobinfo$jobid))
        debugprint("Result: %s", result)
      } else {
        debugprint("OK.\nChecking if job %s is in set %s", jobinfo$jobid, SETQKEY)
        job.ok <- redis.execute.str(connection, c("SISMEMBER", SETQKEY, jobinfo$jobid)) == "1"
        if (!job.ok) {
          debugprint("Job %s not found; removing job.\nFirst: removing payload key %s.", jobinfo$jobid, payloadkey)
          result <- redis.execute.str(connection, c("UNLINK", payloadkey))
          debugprint("Result: %s", result)
        } else {
          debugprint("OK")
        }
      }
      if (!job.ok) {
        # removed payload and jobid from queue set, now we unqueue from stream.
        debugprint("Removing %s from queue stream.", jobinfo$queueid)
        result <- redis.execute.str(connection, c("XDEL", QUEUEKEY, jobinfo$queueid))
        debugprint("Result: %s", result)
      } else {
        debugprint("Checking if payload is compatible with worker")
        if (check.payload.fn(jobinfo$payload)) {
          candidate.queue[[length(candidate.queue) + 1]] <- jobinfo
          debugprint("It is.\nQueueing jobid %s, queueid %s in candidate.queue. %s candidates queued.", jobinfo$jobid, jobinfo$queueid, length(candidate.queue))
        } else {
          debugprint("It is not; ignoring job %s", jobinfo$jobid)
        }
      }
    } else {
      debugprint("No new jobs.")
    }
    DEBUG.jid <<- NULL
    if (length(candidate.queue)) {
      debugprint("Looping over %s internally queued jobs", length(candidate.queue))
    }
    deleting <- numeric(0)
    for (jobinfo.idx in seq_along(candidate.queue)) {
      jobinfo <- candidate.queue[[jobinfo.idx]]
      DEBUG.jid <<- jobinfo$jobid
      debugprint("Doing job: jobid %s, queueid %s", jobinfo$jobid, jobinfo$queueid)

      payloadkey <- sprintf(PAYLOADKEYPATTERN, jobinfo$jobid)
      heartbeatkey <- sprintf(HEARTBEATKEYPATTERN, jobinfo$jobid)

      debugprint("Checking if job %s is in set %s", jobinfo$jobid, SETQKEY)
      job.ok <- redis.execute.str(connection, c("SISMEMBER", SETQKEY, jobinfo$jobid)) == "1"

      if (!job.ok) {
        debugprint("Job %s not found; removing job.", jobinfo$jobid)
      } else {
        debugprint("Trying to acquire heartbeat: set key %s to client id %s", heartbeatkey, clientid)
        heartbeat.created <- redis.execute.str(connection, c("SET", heartbeatkey, clientid, "EX", heartbeatlife, "NX")) == "OK"

        if (!heartbeat.created) {
          debugprint("Heartbeat key already exists. Keeping job %s in the internal queue and trying again next time.", jobinfo$jobid)
          next
        }
        debugprint("Moving job %s from %s to %s", jobinfo$jobid, SETQKEY, SETRKEY)
        job.ok <- redis.execute.str(connection, c("SMOVE", SETQKEY, SETRKEY, jobinfo$jobid)) == "1"

        if (!job.ok) {
          debugprint("Moving was not successful, may be in possession of other runner, maybe was deleted.
Also possible that our heartbeat timed out.\nGetting %s to see if it is still ours", jobinfo$jobid, heartbeatkey)
          hbcontent <- redis.execute.str(connection, c("GET", heartbeatkey))
          if (hbcontent == clientid) {
            debugprint("Returned %s (our id) --> Removing heartbeat key %s", hbcontent, jobinfo$jobid, heartbeatkey)
            result <- redis.execute.str(connection, c("UNLINK", heartbeatkey))
            debugprint("Result: %s", result)
            debugprint("Moving job %s from %s to %s, if present", jobinfo$jobid, SETRKEY, SETDKEY)
            result <- redis.execute.str(connection, c("SMOVE", SETQKEY, SETRKEY, jobinfo$jobid))
            debugprint("Result: %s", result)

          } else {
            debugprint("Returned %s, unlike our id (%s). The job is someone else's problem now.", hbcontent, clientid)
          }
        }
      }

      deleting[[length(deleting) + 1]] <- jobinfo.idx  # delete from internal queue *after* the for-loop, so indices still work until then.

      debugprint("Removing payload key %s.", jobinfo$jobid, payloadkey)
      result <- redis.execute.str(connection, c("UNLINK", payloadkey))
      debugprint("Result: %s", result)
      debugprint("Removing %s from queue stream.", jobinfo$queueid)
      result <- redis.execute.str(connection, c("XDEL", QUEUEKEY, jobinfo$queueid))
      debugprint("Result: %s", result)

      if (!job.ok) {
        debugprint("Finished with job %s", jobinfo$jobid)
        next
      }

      debugprint("Starting to run job %s", jobinfo$jobid)
      jobhandle <- job.initfun(jobinfo$payload)
      debugprint("Job %s is running", jobinfo$jobid)

      heartbeat.present <- TRUE  # when heartbeat expires, this goes to FALSE
      runset.present <- TRUE  # when entry is moved from SETRKEY to SETDKEY, this goes to FALSE
      jobrun.present <- TRUE
      repeat {
        debugprint("Refreshing heartbeat key %s timeout, is %s currently, set to %s.", heartbeatkey, redis.execute.str(connection, c("TTL", heartbeatkey)), heartbeatlife)
        heartbeat.present <- redis.execute.str(connection, c("EXPIRE", heartbeatkey, heartbeatlife)) == "1"

        if (!heartbeat.present) {
          debugprint("Heartbeat key %s not present; killing job.", heartbeatkey)
          break
        }
        debugprint("OK.\nChecking if job %s is still in set %s", jobinfo$jobid, SETRKEY)
        runset.present <- redis.execute.str(connection, c("SISMEMBER", SETRKEY, jobinfo$jobid)) == "1"
        if (!runset.present) {
          debugprint("Job %s not found; killing job.", heartbeatkey)
          break
        }
        debugprint("OK.\nWaiting %s seconds for running job", heartbeatrefresh)

        jobrun.present <- job.evalfun(jobhandle, heartbeatrefresh)

        if (!jobrun.present) {
          debugprint("Job %s finished; removing what remains from it.", jobinfo$jobid)
          break
        }
      }
      if (jobrun.present) {
        job.killfun(jobhandle)
      }

      if (runset.present) {
        debugprint("Moving job %s from %s to %s, if present", jobinfo$jobid, SETRKEY, SETDKEY)
        result <- redis.execute.str(connection, c("SMOVE", SETRKEY, SETDKEY, jobinfo$jobid))
        debugprint("Result: %s", result)
      }
      if (heartbeat.present) {
        debugprint("Removing heartbeat key %s", jobinfo$jobid, heartbeatkey)
        result <- redis.execute.str(connection, c("UNLINK", heartbeatkey))
        debugprint("Result: %s", result)
      }

    }  # loop over internally queued jobs
    candidate.queue[deleting] <- NULL  # delete entries that are either not in the system any more or were handled successfully
  }  # infinite queue polling loop
}

listJobsQueued <- function(connection) {
  # get jobs from SETQKEY
  DEBUG.jid <<- NULL
  on.exit(DEBUG.jid <<- NULL)

  cursor <- "0"
  results <- list()
  repeat {
    debugprint("Getting content of %s with cursor %s", SETQKEY, cursor)
    result <- redis.execute(connection, c("SSCAN", SETQKEY, cursor))
    cursor <- result[[1]]
    foundjobs <- grep(".", result[-1], value = TRUE)  # skip empty lines
    debugprint("Returned %s elements, new cursor %s", length(foundjobs), cursor)
    results[[length(results) + 1]] <- foundjobs
    if (cursor == "0") break
  }
  # get their payload TTL
  # --> -2 (does not exist) ==> do not list as queued. if no heartbeat and no queue entry (same as jobid with "-0") exists, kill it
  # --> -1 ==> list as queued
  # --> other number ==> ignore, still being created
  foundjobs <- unlist(results)
  debugprint("Getting jobs in queue stream")
  queuedjobs <- redis.execute(connection, c("EVAL",
    # get only 2nd element (jobid) of each queue entry
    "local tmp = redis.call('XRANGE', KEYS[1], '0', '+') for key, value in ipairs(tmp) do tmp[key] = value[2][2] end return tmp",
    "1", QUEUEKEY))
  queuedjobs <- grep(".", queuedjobs, value = TRUE)
  debugprint("Got %s jobs in queue stream.", length(queuedjobs))
  debugprint("Found %s jobs in %s, checking them individually", length(foundjobs), SETQKEY)
  Filter(x = foundjobs, f = function(jobid) {
    DEBUG.jid <<- jobid
    payloadkey <- sprintf(PAYLOADKEYPATTERN, jobid)
    debugprint("Checking job %s payload %s", jobid, payloadkey)
    result <- redis.execute.str(connection, c("TTL", payloadkey))
    debugprint("Job %s ttl: %s", jobid, result)
    if (result == "-1") {
      debugprint("Persistent payload, list %s as queued", jobid)
      return(TRUE)
    }
    debugprint("We count %s as not queued, but need to check if we need to kill it.", jobid)
    if (result != "-2") {
      debugprint("Payload has timeout, we count %s as still being created (submitJob has not returned yet)", jobid)
      return(FALSE)
    }
    heartbeatkey <- sprintf(HEARTBEATKEYPATTERN, jobid)
    debugprint("Payload does not exist; we check if we need to delete it.\nSee if heartbeat %s exists", heartbeatkey)
    heartbeat.exists <- redis.execute.str(connection, c("EXISTS", heartbeatkey)) == "1"
    if (heartbeat.exists) {
      debugprint("Exists; job may be on the way to running. Ignoring.")
      return(FALSE)
    }
    debugprint("Heartbeat not found. Check if job is in the queue stream.")
    # streamkey.prior <- paste0(as.integer(jobid) - 1, "-0")
    # streamkey <- paste0(jobid, "-0")
    # debugprint("See if stream has an entry after %s that equals %s", streamkey.prior, streamkey)
    # reply <- redis.execute(connection, c("XREAD", "COUNT", "1", "STREAMS", QUEUEKEY, streamkey.prior))
    if (jobid %in% queuedjobs) {
      debugprint("Job is still in the queue, could potentially still live, so not deleting, but also not listing as scheduled.")
    } else {
      debugprint("Job not found in queue stream, possibly submitJob() died unexpectedly. Deleting the job.")
      result <- redis.execute.str(connection, c("SMOVE", SETQKEY, SETDKEY, jobid))
      debugprint("Result: %s", result)
    }
    return(FALSE)
  })
}

listJobsRunning <- function(connection) {
  # get jobs from SETRKEY
  # if heartbeat does not exist, kill the job (move to D)
  DEBUG.jid <<- NULL
  on.exit(DEBUG.jid <<- NULL)

  cursor <- "0"
  results <- list()
  repeat {
    debugprint("Getting content of %s with cursor %s", SETRKEY, cursor)
    result <- redis.execute(connection, c("SSCAN", SETRKEY, cursor))
    cursor <- result[[1]]
    foundjobs <- grep(".", result[-1], value = TRUE)  # skip empty lines
    debugprint("Returned %s elements, new cursor %s", length(foundjobs), cursor)
    results[[length(results) + 1]] <- foundjobs
    if (cursor == "0") break
  }

  foundjobs <- unlist(results)
  debugprint("Found %s jobs in %s, checking them individually", length(foundjobs), SETRKEY)
  Filter(x = foundjobs, f = function(jobid) {
    DEBUG.jid <<- jobid
    heartbeatkey <- sprintf(HEARTBEATKEYPATTERN, jobid)
    debugprint("Checking job %s heartbeat %s", jobid, heartbeatkey)
    heartbeat.exists <- redis.execute.str(connection, c("EXISTS", heartbeatkey)) == "1"
    if (heartbeat.exists) {
      debugprint("Heartbeat found, %s running.", jobid)
      return(TRUE)
    }
    debugprint("Heartbeat not found, possibly the worker died. Deleting the job.")
    result <- redis.execute.str(connection, c("SMOVE", SETRKEY, SETDKEY, jobid))
    debugprint("Result: %s", result)
    return(FALSE)
  })
}

makeClusterFunctionsRedis <- function(redisdir, pollrate = 0.1, fs.latency = 65, payloadlifetime = HEARTBEATLIFETIME) {
  xcon <- redis.initiate(redisdir, pollrate = pollrate)

  batchtools::makeClusterFunctions(name = "REDIS",
    submitJob = function(reg, jc) {
      jobid <- submitJob(xcon, payload = jc, payloadlifetime = payloadlifetime)
      batchtools::makeSubmitJobResult(0, jobid)
    },
    killJob = function(reg, batch.id) {
      killJob(xcon, jobid = batch.id)
    },
    listJobsQueued = function(reg) {
      listJobsQueued(xcon)
    },
    listJobsRunning = function(reg) {
      listJobsRunning(xcon)
    },
    store.job.collection = FALSE,
    fs.latency = fs.latency
  )
}

workerBatchtools <- function(redisdir, mem.available = Inf, walltime.available = Inf, die.on.timeout = TRUE,
    pollrate = 0.1, heartbeatlife = HEARTBEATLIFETIME, heartbeatrefresh = HEARTBEATREFRESHINT) {

  endtime <- as.numeric(Sys.time()) + walltime.available

  xcon <- redis.initiate(redisdir, pollrate = pollrate)

  checkPayload <- function(jc) {
    if (jc$resources$ncpus %??% 1 != 1) return(FALSE)
    if (jc$resources$memory > mem.available) return(FALSE)
    if (as.numeric(Sys.time()) + jc$resources$walltime > endtime) {
      if (die.on.timeout) {
        stopf("Got Job with too large timeout. Killing this worker to make room for another worker with more timeout.")
      } else {
        return(FALSE)
      }
    }
    TRUE
  }
  initWorker <- function(jc) {
    debugprint("Running job batchtools id %s; writing to file %s", paste(jc$jobs$job.id, collapse = ", "), jc$log.file)
    session <- NULL
    trycounter <- 0
    while (is.null(session)) {
      session <- tryCatch({
        session <- callr::r_session$new(wait_timeout = 10000)
        # without the function(...), batchtools namespace is not loaded
        session$call(function(...) batchtools::doJobCollection(...), args = list(jc, output = jc$log.file))
        session
      }, error = function(e) {
        debugprint("Error:\n%s\nsleeping for 10 seconds...", e$message)
        Sys.sleep(10)
        if (trycounter < 30) debugprint("retrying")
        NULL
      })
      trycounter <- trycounter + 1
      if (trycounter > 30) {
        debugprint("Giving up on starting job.")
        stop("Could not start R session after 31 tries.")
      } 
    }
    debugprint("callr session started")
    list(session = session, endtime = as.numeric(Sys.time()) + jc$resources$walltime)
  }
  evalWorker <- function(job, timeout) {
    time.remaining <- job$endtime - as.numeric(Sys.time())
    debugprint("Walltime remaining: %.3fs", time.remaining)
    if (time.remaining < 0) {
      debugprint("Killing immediately (out of time)")
      response <- FALSE
      return(FALSE)
    }
    if (time.remaining < timeout) {
      debugprint("Running for shorter time %.3fs", time.remaining)
      status <- job$session$poll_process(round(time.remaining * 1000))
      debugprint("Killing after timeout, status was %s", status)
      response <- FALSE
    } else {
      debugprint("Running with ordinary timeout %.3fs", timeout)
      status <- job$session$poll_process(round(timeout * 1000))
      debugprint("Polling end; status: %s", status)
      response <- status == "timeout"
    }
    if (!response) killWorker(job)
    return(response)
  }
  killWorker <- function(job) {
    debugprint("Killing job forcefully.")
    job$session$close()
  }

  worker(xcon, check.payload.fn = checkPayload, job.initfun = initWorker, job.evalfun = evalWorker, job.killfun = killWorker,
    heartbeatlife = heartbeatlife, heartbeatrefresh = heartbeatrefresh)
}

###################### preliminary ideas: ###########################

# add job:
#   - increment number
#   - add JC to pending hash(?)set
# worker:
#   - react to new elements in the set
#   - check if the new element can be used
#   - try to acquire the element
#   - heartbeat
#   - result: update result if hearbeat is not timed out
# status:
#     - in resultsset --> given result
#     - nowhere: died
#     - heartbeat timeout: died
#


# add job:
#   - XADD <key> * <field> <value> [<field> <value> ...]
# kill job:
#   - XDEL
#   - kill heartbeat
# worker:
#   - iterate through LASTINDEX, starting from 0:
#       - XREAD COUNT 1 BLOCK <millis> STREAMS <key> <LASTINDEX>
#       - if result can be evaluated: (1) claim (2) evaluate
#   - CLAIM:
#     - mark as running: add 'running' heartbeat
#     - XDEL <LASTINDEX>. check if return value is 1, otherwise was killed
#   - EVALUATE: poll
#     - heartbeat killed --> kill job
#     - job killed --> kill heartbeat

###################### analysis: ###########################

# (not entirely correct but close enough)

# job has the following states:
# * EPL (payload exists): T, F
# * EQE (queue entry exists): T, F
# * EHB (heartbeat exists): T, F
# * JSP (job set position): 'queued', 'running', 'dead', ''

# | State# | EPL | EQE | EHB | JSP       | meaning
# |-------:|:----|:----|:----|:----------|:----------------
# |      1 | F   | F   | F   | 'queued'  | happens if job creation times out. submitJob() ==>#7; listJobsQueued() ==>#25; killJob() ==> #3
# |      2 | F   | F   | F   | 'running' | officially dead. killJob(),worker() ==>#3
# |      3 | F   | F   | F   | 'dead'    | DEAD
# |      4 | F   | F   | T   | 'queued'  |
# |      5 | F   | F   | T   | 'running' | killJob(), worker() ==> #6 job end (naturally or unnaturally). hbto ==> #2
# |      6 | F   | F   | T   | 'dead'    | worker(),hbto,killJob() ==>#3
# |      7 | F   | T   | F   | 'queued'  | submitted but plto. worker() ==>#27. worker(#19) ==>#10. killJob() ==>#9, submitJob() ==>#27
# |      8 | F   | T   | F   | 'running' | worker() ==>#2, killJob() ==>#9
# |      9 | F   | T   | F   | 'dead'    | killJob() does not touch this. worker(),submitJob() ==>#3
# |     10 | F   | T   | T   | 'queued'  | worker in process of accepting a job, PL expired. worker() ==>#11, submitJob() ==>#28
# |     11 | F   | T   | T   | 'running' | worker about to run job. (self or other) worker() ==>#5, heartbeat timeout ==>#8 killJob() ==>#12.
# |     12 | F   | T   | T   | 'dead'    | killJob(), heartbeat timeout ==>#9, other worker() ==>#6
# |     13 | T   | F   | F   | 'queued'  | job is being created. submitJob() ==>#19; if PL times out ==>#1. killJob() ==> #15
# |     14 | T   | F   | F   | 'running' |
# |     15 | T   | F   | F   | 'dead'    | killJob(),plto ==> #3. submitJob() ==>#21, other worker()==>#3
# |     16 | T   | F   | T   | 'queued'  |
# |     17 | T   | F   | T   | 'running' | UNREACHABLE: only worker() and submitJob() can remove queue entry, which they only do after EPL is F
# |     18 | T   | F   | T   | 'dead'    |
# |     19 | T   | T   | F   | 'queued'  | queue state, submitJob() ordinary success state. worker() ==>#22. could transition to #7 at any point. killJob() ==>#21
# |     20 | T   | T   | F   | 'running' | officially dead, but worker doesn't know yet. (self and other) worker(),plto ==>#8. killJob() ==>#21
# |     21 | T   | T   | F   | 'dead'    | plto,killJob(), other worker() ==>#9; submitJob() does not act on this state!
# |     22 | T   | T   | T   | 'queued'  | worker is in the process of acquiring this. worker() ==>#23. PL timeout #10. killJob() ==>#24
# |     23 | T   | T   | T   | 'running' | job no longer 'queued' and instead 'running'. killJob() ==>#24. plto,worker() ==>#11. hbto ==>#20. other worker() ==>#11
# |     24 | T   | T   | T   | 'dead'    | killJob(),plto,other worker() ==>#12; hbto ==>#21, worker ==>#12
# |     25 | F   | F   | F   | ''        | job does not exist. submitJob() ==> #29 ordinarily, or ==>#1 if coming from #29
# |     26 | F   | F   | T   | ''        | hbto ==>#25
# |     27 | F   | T   | F   | ''        | submitJob(),worker() ==>#25
# |     28 | F   | T   | T   | ''        | weird state; PL timed out while submitJob() and worker() are accessing things... other worker(),submitJob() ==>#26
# |     29 | T   | F   | F   | ''        | job being created. submitJob() ==>#13; if PL times out, ==>#25
# |     30 | T   | F   | T   | ''        |
# |     31 | T   | T   | F   | ''        |
# |     32 | T   | T   | T   | ''        |

## unfortunately there is a small chance that some other worker acquires the heartbeat after it timed out if the first worker hangs after getting heartbeat but
# before setting queue status to running

# create job: key with payload and timeout
# add into 'queued' set
# enqueue
# make job key persistent. check if job still exists. if not, it was either picked up or we are too late
#   delete entry from 'queued' (not adding it to 'running' or 'dead')
#   remove queue entry. this is done by workers that find a queue entry without payload, so no info here
#   check if entry is in 'running' or 'dead'; if so: job was picked up. otherwise: we (or someone else) deleted it, it was never really scheduled, we try again.

# worker:
# (a bit obsolete, some minor mistakes)
# wait for queue with HEARTBEATLIFETIME + random timeout
# |                              | if job found:
# |                              |   read job content
# | 7->27->25,9->3,28->26        |   job key not found --> delete entry from 'queued', delete queue entry, next
# | 23->11->5,21->9->3,24->12->6,20->8->2,28->26 |   not in 'queued' --> delete PL, delete queue entry, next
# |                              |   check if accepting; if not, next, otherwise: add to list of candidates
# |                              | for list of candidates:
# | 23->11,15->3                 |   if not in 'queued' --> do as above? #### remove from list, remove PL, remove queue entry, next
# | 19->22,7->10                 |   create heartbeat, if not successful, next, candidate stays in list
# |                              |   remove from candidate list
# | 22->23,10->11                |   move from 'queued' to 'running', if not successful, do the next two steps and then delete
# | 23->11,24->12,20->8,21->9    |   delete PL, ignore if not successful
# | 11->5,8->2,9->3,12->6        |   delete queue entry, ignore if not successful
# |                              |   start running job
# |                              |   while job is running {
# | 2->3                         |     if update heartbeat; if heartbeat is dead --> move from 'running' to 'dead'
# |                              |     if entry is in 'dead' --> kill job
# |                              |   }
# | 5->6->3                      |   move job from 'running' to 'dead', remove heartbeat

# killJob()
# queued -> dead
# running -> dead
# remove job payload
# remove heartbeat
# (do not remove from queue: we don't know the queue id, workers will take care of this; it also protects us from having job payload linger)

# listJobsQueued()
#
#

# listJobsRunning()


# batchtools integration

## worker.acceptJob <- function(jc, ...) {
##   # check whether job is acceptable
##   # jc is a batchtools::JobCollection
## }


# ---------------- debugging


