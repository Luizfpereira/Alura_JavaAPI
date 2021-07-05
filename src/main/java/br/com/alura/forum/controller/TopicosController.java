package br.com.alura.forum.controller;

import br.com.alura.forum.form.TopicoForm;
import br.com.alura.forum.modelo.Curso;
import br.com.alura.forum.modelo.Topico;
import br.com.alura.forum.repository.CursoRepository;
import br.com.alura.forum.repository.TopicoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/topico")
public class TopicosController {

    @Autowired
    private TopicoRepository topicoRepository;

    @Autowired
    private CursoRepository cursoRepository;

    @GetMapping
    public List<TopicoDto> lista(String nomeCurso){
        List<Topico> topicos = null;
        if (nomeCurso == null){
            topicos = topicoRepository.findAll();
        } else {
            topicos = topicoRepository.findByCursoNome(nomeCurso);
        }
        return TopicoDto.converter(topicos);
    }

    @GetMapping("/{id}")
    public DetalhesDoTopicoDto detalhar(@PathVariable Long id){
        Topico topico = topicoRepository.getOne(id);
        return new DetalhesDoTopicoDto(topico);
    }

    @PostMapping
    public ResponseEntity<TopicoDto> cadastrar(@RequestBody @Valid TopicoForm form, UriComponentsBuilder uriBuilder){
        Topico topico = form.converter(cursoRepository);
        topicoRepository.save(topico);
        URI uri = uriBuilder.path("/topico/{id}").buildAndExpand(topico.getId()).toUri();
        return ResponseEntity.created(uri).body(new TopicoDto(topico));
    }

    
}
