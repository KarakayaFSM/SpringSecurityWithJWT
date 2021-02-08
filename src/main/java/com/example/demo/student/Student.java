package com.example.demo.student;

public class Student {

    private final Integer studentId;
    private final String studentName;

    public Student(Integer studentId,
                   String studentName) {
        this.studentId = studentId;
        this.studentName = studentName;
    }

    public Integer getId() {
        return studentId;
    }

    public String getName() {
        return studentName;
    }
}
