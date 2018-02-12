-module(ppal_uri).

extract_idx(_Subject, {-1,0}) -> undefined;
extract_idx(Subject, {Offset,Length}) -> lists:sublist(Subject, Offset+1, Length).

parse_uri(Uri) ->
    Regex = "(?<scheme>[^:]+)://((?<userinfo>[^@])@)?(?<host>[^/:?#]+)(:(?<port>\\d+))?(/.*)?$",
    case re:run(Uri, Regex, [{capture, [scheme, userinfo, host, port]}]) of
        {match, [SchemeIdx, UserInfoIdx, HostIdx, PortIdx]} ->
            {ok, {extract_idx(Uri, SchemeIdx),
                  extract_idx(Uri, UserInfoIdx),
                  extract_idx(Uri, HostIdx),
                  extract_idx(Uri, PortIdx)}};
        nomatch -> {error, nomatch};
        Else -> Else
    end.
