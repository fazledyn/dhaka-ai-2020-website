drop table if exists Participant;
drop table if exists Leaderboard;
drop table if exists Team;


create table Team
(
    TeamName varchar(25) not null,
    Password varchar(400) not null,
    EmailAddress varchar(50),
    EmailToken varchar(200) not null,
    isApproved integer default 0,
    isVerified integer default 0,
    isAdmin integer default 0,
    DailyLimit integer default 0,
    DateCreated DATE,
    primary key (TeamName)
);

create table Participant
(
    id integer not null AUTO_INCREMENT PRIMARY KEY,
	Name varchar(40),
	ContactNo varchar(20),
	Institution varchar(50),
	TeamName varchar(25),
	foreign key (TeamName) references Team(TeamName)
);

SET time_zone = '+06:00';

create table Leaderboard
(   
    id integer not null AUTO_INCREMENT PRIMARY KEY,
    TeamName varchar(25),
	Accuracy double,
	SolutionPath varchar(150),
    SubmissionTime DATETIME,
    SubmissionStatus varchar(10),
	foreign key (TeamName) references Team(TeamName)
);
