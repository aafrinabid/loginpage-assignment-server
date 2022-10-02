CREATE TABLE user (
    id uuid DEFAULT uuid_generate_v4(),
    username VARCHAR,
    email VARCHAR,
    password VARCHAR,
    mobile_number VARCHAR,
    PRIMARY KEY (id)

)


CREATE TABLE user_session (
    session_id uuid DEFAULT uuid_generate_v4(),
    user_id uuid,
    message VARCHAR,
    login_time VARCHAR,
    session_time VARCHAR DEFAULT '5',
    PRIMARY KEY (session_id),
    FORIEGN KEY (user_id)
    REFERENCES user(id)

)
