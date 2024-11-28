package com.cnf.daos;

import lombok.Data;

import java.util.Date;

@Data
public class CommentDTO {
    private long id;
    private String comment_text;
    private int rating;
    private Date date;
    private String user_name;
    private String user_img;
}
