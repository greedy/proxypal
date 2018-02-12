-module(ppal_http_session).
-behavior(gen_statem).

-export([start_link/1]).
-export([init/1, callback_mode/0, handle_event/4, terminate/3]).

-record(data, {clientsocket, clientdata = <<>>, req, hdrs={<<>>,[]}}).

start_link(ClientSocket) ->
    gen_statem:start_link(?MODULE, ClientSocket, []).

callback_mode() ->
    state_functions.

init(ClientSocket) ->
    {ok, read_start_line, #data{clientsocket=ClientSocket},
     {state_timeout, 1000, []}}.

part_before(Binary, Suffix) ->
    binary:part(Binary, 0, byte_size(Binary) - byte_size(Suffix)).

read_start_line(enter, _OldState, Data=#data{clientsocket=S}) ->
    inet:setopts(S, [{active, once}, {packet, raw}]),
    keep_state_and_data;
read_start_line(info, {tcp, S, Pkt}, Data=#data{clientsocket=S}) ->
    NewPkt = <<(Data#data.clientdata)/binary, Pkt/binary>>,
    case erlang:decode_packet(http, NewPkt, []) of
        {ok, ParsedReq={http_request, _, _, _}, Rest} ->
            RawReq = part_before(NewPkt, Rest),
            {next_state, read_headers, Data#data{clientdata=<<>>, req={RawReq,ParsedReq}},
             {next_event, info, {tcp, S, Rest}}};
        {more, _Length} ->
            inet:setopts(S, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{clientdata=NewPkt}};
        {error, Reason} ->
            {stop, Reason}
    end.

read_headers(enter, _OldState, _Data) ->
    % read_start_line pumps this state with a synthetic tcp pkt
    % so no need to set the socket active
    keep_state_and_data;
read_headers(info, {tcp, S, Pkt},
             Data=#data{clientsocket=S, clientdata=CD, hdrs={RawHdrs, ParsedHdrs}})
->
    NewPkt = <<CD/binary, Pkt/Binary>>,
    case erlang:decode_packet(httph, NewPkt, []) of
        {ok, ParsedHdr={http_header, _, _, _}, Rest} ->
            RawHdr = part_before(NewPkt, Rest),
            {next_state, read_headrs, Data#data{clientdata=<<>>,
                                                hdrs={<<RawHdrs/binary, RawHdr/binary>>,
                                                      [ParsedHdr|ParsedHdrs]}},
             {next_event, info, {tcp, S, Rest}}};
        {ok, http_eoh, Rest} ->
            handle_request(Data#data{clientdata=Rest,
                                     hdrs={RawHdrs, list:reverse(ParsedHdrs)}});
        {more, _Length} ->
            inet:setopts(S, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{clientdata=NewPkt}};
        {error, Reason} ->
            {stop, Reason}
    end.

portstr(undefined) -> "";
portstr(Num) -> [":", number_to_list(Num)].

handle_request(Data=#data{req={RawReq,ParsedReq},
                          hdrs={RawHdrs,ParsedHdrs}}) ->
    {http_request, Method, Uri, Version} = ParsedReq,
    {absoluteURI, Scheme, Host, Port, Path},
    UrlStr = lists:flatten([atom_to_list(Scheme), "://", Host, portstr(Port), Path]),
    Proxies = ppal_proxylookup:proxies_for_url(UrlStr),
