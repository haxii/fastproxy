init = function(args)
    target_url = args[1] -- proxy needs absolute URL
end

wrk.headers["Cache-Control"] = "no-cache"
request = function()
    return wrk.format("GET", target_url)
end