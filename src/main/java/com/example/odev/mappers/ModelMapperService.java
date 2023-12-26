package com.example.odev.mappers;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;

public interface ModelMapperService {
    @Autowired
    ModelMapper forResponse();
}
