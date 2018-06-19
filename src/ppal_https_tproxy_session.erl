-module(ppal_https_tproxy_session).
-behavior(gen_statem).

-include("linux_socket.hrl").

-export([start_link/1]).
-export([init/1, callback_mode/0, terminate/3]).

-export([wait_for_proxy_response/3, read_resp_headers/3, forward_data/3]).

-record(data, {localsocket, remotesocket,
               remotedata = <<>>}).

start_link(ClientSocket) ->
    gen_statem:start_link(?MODULE, ClientSocket, []).

callback_mode() ->
    [state_functions, state_enter].

init(ClientSocket) ->
    {ok, {Ip, Port}} = inet:sockname(ClientSocket),
    IpString = inet:ntoa(Ip),
    UrlStr = lists:flatten(["https://", IpString]),
    [FirstProxy|_Proxies] = ppal_proxylookup:proxies_for_url(UrlStr),
    {ok, ParsedProxy={ProxyScheme, _UserInfo, _Host, _Port}} = ppal_uri:parse_uri(FirstProxy),
    case ProxyScheme of
        "direct" -> direct_connect(ClientSocket, Ip, 443);
        "http" -> http_connect(ClientSocket, Ip, 443, ParsedProxy)
    end.

direct_connect(ClientSocket, Ip, Port) ->
    {ok, Socket} = gen_tcp:connect(Ip, Port,
                                   [binary, {active, false},
                                    {raw, ?SOL_SOCKET, ?SO_MARK, ?IntOpt(101)}]),
    {ok, forward_data, #data{localsocket=ClientSocket, remotesocket=Socket}}.

http_connect(ClientSocket, Ip, Port, {"http", ProxyUserInfo, ProxyHost, ProxyPort}) ->
    ActualPort = case ProxyPort of undefined -> 80; _ -> list_to_integer(ProxyPort) end,
    {ok, Socket} = gen_tcp:connect(ProxyHost, ActualPort,
                                   [binary, {active, false},
                                    {raw, ?SOL_SOCKET, ?SO_MARK, ?IntOpt(101)}]),
    ok = gen_tcp:send(Socket, ["CONNECT ", inet:ntoa(Ip), ":", integer_to_list(Port), " HTTP/1.1\r\n"]),
    case ProxyUserInfo of
        undefined -> ok;
        _ -> ok = gen_tcp:send(Socket, ["Proxy-Authorization: Basic ",
                                        base64:encode(ProxyUserInfo),
                                        "\r\n"])
    end,
    ok = gen_tcp:send(Socket, "\r\n"),
    {ok, wait_for_proxy_response, #data{localsocket=ClientSocket, remotesocket=Socket}}.

wait_for_proxy_response(enter, _OldState, _Data) ->
    keep_state_and_data;
wait_for_proxy_response(info, own_socket, Data) ->
    inet:setopts(Data#data.remotesocket, [{active, once}, binary, {packet, raw}]),
    keep_state_and_data;
wait_for_proxy_response(info, {tcp, RemoteSocket, Pkt}, Data=#data{localsocket=LocalSocket, remotesocket=RemoteSocket}) ->
    NewPkt = <<(Data#data.remotedata)/binary, Pkt/binary>>,
    case erlang:decode_packet(http, NewPkt, []) of
        {ok, {http_response, HttpVersion, 200, Message}, Rest} ->
            {next_state, read_resp_headers, Data#data{remotedata=(<<>>)},
             {next_event, info, {tcp, RemoteSocket, Rest}}};
        {ok, {http_response, HttpVersion, Status, Message}, Rest} ->
            {stop, {Status, Message}};
        {more, _Length} ->
            inet:setopts(RemoteSocket, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{remotedata=NewPkt}};
        {error, Reason} ->
            {stop, Reason}
    end.

read_resp_headers(enter, _OldState, _Data) ->
    keep_state_and_data;
read_resp_headers(info, {tcp, RemoteSocket, Pkt}, Data=#data{localsocket=LocalSocket, remotesocket=RemoteSocket}) ->
    NewPkt = <<(Data#data.remotedata)/binary, Pkt/binary>>,
    case erlang:decode_packet(httph, NewPkt, []) of
        {ok, http_eoh, Rest} ->
            {next_state, forward_data, Data#data{remotedata=(<<>>)},
             {next_event, info, {tcp, RemoteSocket, Rest}}};
        {ok, _Hdr, Rest} ->
            {keep_state, Data#data{remotedata=Rest}};
        {more, _Length} ->
            inet:setopts(RemoteSocket, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{remotedata=NewPkt}};
        {error, Reason} ->
            {stop, Reason}
    end.

forward_data(enter, _, #data{localsocket=CS, remotesocket=DS}) ->
    inet:setopts(CS, [{active, once}]),
    inet:setopts(DS, [{active, once}]),
    keep_state_and_data;
forward_data(info, {tcp, CS, Pkt}, #data{localsocket=CS, remotesocket=DS}) ->
    ok = gen_tcp:send(DS, Pkt),
    repeat_state_and_data;
forward_data(info, {tcp, DS, Pkt}, #data{localsocket=CS, remotesocket=DS}) ->
    ok = gen_tcp:send(CS, Pkt),
    repeat_state_and_data;
forward_data(info, {tcp_closed, _}, _Data) ->
    stop.

terminate(_Reason, _State, Data) ->
    gen_tcp:close(Data#data.localsocket),
    case Data#data.remotesocket of
        undefined -> ok;
        DS -> gen_tcp:close(DS)
    end.
