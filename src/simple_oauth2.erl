-module(simple_oauth2).
-author('Igor Milyakov <virtan@virtan.com>').

-export([
        dispatcher/3,
        predefined_networks/0, customize_networks/2,
        gather_url_get/1
    ]).

predefined_networks() ->
    [
        {<<"facebook">>, [ % https://developers.facebook.com/apps/
                {client_id, <<"...">>},
                {client_secret, <<"...">>},
                {callback_uri, <<"/auth/facebook/callback">>},
                {scope, <<"email">>},
                {authorize_uri, <<"https://www.facebook.com/dialog/oauth">>},
                {token_uri, <<"https://graph.facebook.com/oauth/access_token">>},
                {userinfo_uri, <<"https://graph.facebook.com/me">>},
                {userinfo_params, [{access_token, access_token},
                        {fields, <<"id,email,name,picture,gender,locale">>}]},
                {field_names, [id, email, name, undefined, gender, locale]}
            ]},
        {<<"github">>, [
                {client_id, <<"...">>},
                {client_secret, <<"...">>},
                {callback_uri, <<"/auth/github/callback">>},
                {scope, <<>>},
                {authorize_uri, <<"https://github.com/login/oauth/authorize">>},
                {token_uri, <<"https://github.com/login/oauth/access_token">>}
            ]},
        {<<"google">>, [ % https://code.google.com/apis/console/b/0/
                {client_id, <<"...">>},
                {client_secret, <<"...">>},
                {callback_uri, <<"/auth/google/callback">>},
                {scope, << "https://www.googleapis.com/auth/userinfo.email ",
                    "https://www.googleapis.com/auth/userinfo.profile" >>},
                {authorize_uri, <<"https://accounts.google.com/o/oauth2/auth">>},
                {token_uri, <<"https://accounts.google.com/o/oauth2/token">>},
                {userinfo_uri, <<"https://www.googleapis.com/oauth2/v1/userinfo">>},
                {userinfo_params, [{access_token, access_token}]},
                {field_names, [id, email, name, picture, gender, locale]}
            ]},
        {<<"mailru">>, [
                {client_id, <<"...">>},
                {client_secret, <<"...">>},
                {secret_key, <<"f431aea09762dbad13c2440955e12aee">>},
                {callback_uri, <<"/auth/mailru/callback">>},
                {scope, <<>>},
                {authorize_uri, <<"https://connect.mail.ru/oauth/authorize">>},
                {token_uri, <<"https://connect.mail.ru/oauth/token">>}
            ]},
        {<<"paypal">>, [
                {client_id, <<"...">>},
                {client_secret, <<"...">>},
                {callback_uri, <<"/auth/paypal/callback">>},
                {scope, <<"https://identity.x.com/xidentity/resources/profile/me">>},
                {authorize_uri, <<"https://identity.x.com/xidentity/resources/authorize">>},
                {token_uri, <<"https://identity.x.com/xidentity/oauthtokenservice">>}
            ]},
        {<<"vkontakte">>, [ % http://vk.com/dev
                {client_id, <<"...">>},
                {client_secret, <<"...">>},
                {callback_uri, <<"/auth/vkontakte/callback">>},
                {scope, <<"uid,first_name,last_name,sex,photo">>},
                {authorize_uri, <<"https://oauth.vk.com/authorize">>},
                {token_uri, <<"https://oauth.vk.com/access_token">>},
                {userinfo_uri, <<"https://api.vk.com/method/users.get">>},
                {userinfo_params, [{access_token, access_token},
                        {fields, <<"uid,first_name,last_name,sex,photo">>}]},
                {field_names, [uid, undefined, first_name, photo, sex, undefined]},
                {field_pre, fun(Profile) -> hd(proplists:get_value(<<"response">>, Profile)) end}
            ]},
        {<<"yandex">>, [ % https://oauth.yandex.ru/client/new
                {client_id, <<"...">>},
                {client_secret, <<"...">>},
                {callback_uri, <<"/auth/yandex/callback">>},
                {scope, <<>>},
                {authorize_uri, <<"https://oauth.yandex.ru/authorize">>},
                {token_uri, <<"https://oauth.yandex.ru/token">>},
                {userinfo_uri, <<"https://login.yandex.ru/info">>},
                {userinfo_params, [{oauth_token, access_token}, {format, <<"json">>}]},
                {field_names, [id, default_email, display_name, picture, sex, undefined]}
            ]}
    ].

customize_networks(Networks, Customization) ->
    [
        {Network, fun() ->
           CustOpts = proplists:get_value(Network, Customization),
           {_, Rem} = proplists:split(Options, proplists:get_keys(CustOpts)),
           CustOpts ++ Rem
           end()}
        || {Network, Options} <- Networks,
           proplists:get_value(Network, Customization, undefined) =/= undefined
    ].

parse_gets(<<>>) -> [];
parse_gets(GetString) ->
    [{list_to_binary(K), list_to_binary(V)} ||
        {K, V} <- httpd:parse_query(binary_to_list(GetString))].

dispatcher(Request, LocalUrlPrefix, Networks) -> 
    [Path | PreGets] = binary:split(Request, <<"?">>),
    [NetName, Action] = binary:split(Path, <<"/">>),
    Gets = case PreGets of
        [] -> [];
        [QString] -> parse_gets(QString)
    end,
    Network = proplists:get_value(NetName, Networks),
    case {Network, Action} of
        {undefined, _} -> {error, unknown_network, "Unknown or not customized social network"};
        {_, <<"login">>} ->
            {redirect,
                {proplists:get_value(authorize_uri, Network), [
                    {client_id, proplists:get_value(client_id, Network)},
                    {redirect_uri, iolist_to_binary([LocalUrlPrefix,
                                proplists:get_value(callback_uri, Network)])},
                    {response_type, proplists:get_value(<<"response_type">>, Gets, <<"code">>)},
                    {scope, proplists:get_value(scope, Network)},
                    {state, proplists:get_value(<<"state">>, Gets, <<>>)}
                ]}
            };
        {_, <<"callback">>} ->
            case proplists:get_value(<<"error">>, Gets, undefined) of
                undefined -> case proplists:get_value(<<"code">>, Gets, undefined) of
                        undefined -> case proplists:get_value(<<"access_token">>, Gets, undefined) of
                                undefined -> {send_html, <<
                                        "<!--script>",
                                        "window.location.replace(window.location.href.replace('#','?'))",
                                        "</script-->"
                                    >>};
                                Token -> {ok, get_profile_info(Network, [
                                        {network, NetName},
                                        {access_token, Token},
                                        {token_type, proplists:get_value(<<"token_type">>, Gets,
                                                <<"bearer">>)}
                                    ])}
                            end;
                        Code ->
                            post({NetName, Network}, proplists:get_value(token_uri, Network), [
                                {code, Code},
                                {client_id, proplists:get_value(client_id, Network)},
                                {client_secret, proplists:get_value(client_secret, Network)},
                                {redirect_uri, iolist_to_binary([LocalUrlPrefix,
                                            proplists:get_value(callback_uri, Network)])},
                                {grant_type, <<"authorization_code">>}
                            ])
                    end;
                Error -> {error, auth_error, Error}
            end
    end.

urlencoded_parse(Data) ->
    Parsed = parse_gets(Data),
    ParsedLength = length(Parsed),
    CleanLength = length([{K, V} || {K, V} <- Parsed, K =/= <<>>, V =/= <<>>]),
    io:format("~p ~p ~p ~p~n", [Data, Parsed, ParsedLength, CleanLength]),
    if
        CleanLength == ParsedLength -> Parsed;
        true -> {error, json_error, "Can't parse json"}
    end.

json_parse(JSON) ->
    case jsx:decode(JSON, [{error_handler, fun(_, _, _) -> {error, unsuccessful} end}]) of
        {error, _} -> urlencoded_parse(JSON);
        {incomplete, _} -> urlencoded_parse(JSON);
        Parsed -> Parsed
    end.

http_request_json(Method, Request, OnSuccess) ->
    case httpc:request(Method, Request,
            [{timeout, 10000}, {connect_timeout, 20000}, {autoredirect, true}],
            [{body_format, binary}, {full_result, false}]) of
        {ok, {200, JSON}} -> OnSuccess(JSON);
        {ok, {Code, _}} -> {error, post_error, lists:flatten("Post returned non-200 code: " ++
                    integer_to_list(Code))};
        {error, Reason} -> {error, http_request_error, Reason}
    end.

post({NetName, Network}, Url, Params) ->
    http_request_json(post, {binary_to_list(Url), [], "application/x-www-form-urlencoded",
            url_encode(Params)},
        fun(JSON) -> io:format("~p~n", [JSON]), case json_parse(JSON) of
                {error, _, _} = Error -> Error;
                Hash -> case proplists:get_value(<<"error">>, Hash, undefined) of
                        undefined -> {ok, get_profile_info(Network, [
                            {network, NetName},
                            {access_token, proplists:get_value(<<"access_token">>, Hash)},
                            {token_type, proplists:get_value(<<"token_type">>, Hash, <<"bearer">>)}
                        ])};
                        Error -> {error, unsuccessful, Error}
                    end
            end
        end).

url_encode(Data) -> url_encode(Data,"").
url_encode([],Acc) -> list_to_binary(Acc);
url_encode([{Key,Value}|R],"") ->
    url_encode(R, edoc_lib:escape_uri(atom_to_list(Key)) ++ "=" ++
        edoc_lib:escape_uri(binary_to_list(Value)));
url_encode([{Key,Value}|R],Acc) ->
    url_encode(R, Acc ++ "&" ++ edoc_lib:escape_uri(atom_to_list(Key)) ++ "=" ++
        edoc_lib:escape_uri(binary_to_list(Value))).

gather_url_get({Path, QueryString}) ->
    iolist_to_binary([Path,
        case lists:flatten([
            ["&", edoc_lib:escape_uri(atom_to_list(K)), "=", edoc_lib:escape_uri(binary_to_list(V))]
            || {K, V} <- QueryString
        ]) of [] -> []; [_ | QS] -> [$? | QS] end]).

get_profile_info(Network, Auth) ->
    http_request_json(get, {binary_to_list(gather_url_get(
                    {proplists:get_value(userinfo_uri, Network), lists:map(fun({K, access_token}) ->
                                    {K, proplists:get_value(access_token, Auth)};
                                (P) -> P end, proplists:get_value(userinfo_params, Network))
                        })), []},
            fun(JSON) -> io:format("~p~n", [JSON]), case json_parse(JSON) of
                {error, _, _} = Error -> Error;
                Profile -> Profile1 = case proplists:get_value(field_pre, Network) of
                        undefined -> Profile; F -> F(Profile) end,
                    [{Field, proplists:get_value(list_to_binary(atom_to_list(Name)), Profile1)}
                        || {Field, Name} <- lists:zip([id, email, name, picture, gender, locale],
                        proplists:get_value(field_names, Network))] ++ Auth
            end
        end).
