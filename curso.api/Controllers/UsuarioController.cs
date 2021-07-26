using curso.api.Business.Entities;
using curso.api.Filters;
using curso.api.Infraestruture.Data;
using curso.api.Models.Usuarios;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace curso.api.Controllers
{
    [Route("api/v1/usuario")]
    [ApiController]
    public class UsuarioController : ControllerBase
    {
        private object usuarioViewModelOutput;

        /// <summary>
        /// Este serviço permite cadastrar curso para o usuário autenticado.
        /// </summary>
        /// <param name="loginViewModelInput"></param>
        /// <returns>Retorna status 201 e dados do curso do usuario</returns>

        [SwaggerResponse(statusCode: 200, description: "Sucesso ao autenticar", Type =typeof(LoginViewModelInput))]
        [SwaggerResponse(statusCode: 400, description: "Campos Obrigatórios", Type = typeof(ValidaCampoViewModelOutput))]
        [SwaggerResponse(statusCode: 500, description: "Erro interno", Type = typeof(ErroGenericoViewModel))]
        [HttpPost]
        [Route("logar")]
        [ValidacaoModelStateCustomizado]
        public IActionResult Logar(LoginViewModelInput loginViewModelInput)
        {
            //if (!modelstate.isvalid)
            //{
            //    return badrequest(new validacampoviewmodeloutput(modelstate.selectmany(sm => sm.value.errors).select(s => s.errormessage)));
            //}

            var usuarioViewModelOutput = new UsuarioViewModelOutput()
            { 
                Codigo = 1,
                Login = "diegogalli",
                Email = "diegogalli2@gmail.com"                
            };

            var secret = Encoding.ASCII.GetBytes("MzfsT&d9gprP>!9$Es(X!5g@;ef!5sbk:jH\\2.}8ZP'Qy#7");
            var symmetricSecurityKey = new SymmetricSecurityKey(secret);
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, usuarioViewModelOutput.Codigo.ToString()),
                    new Claim(ClaimTypes.Name, usuarioViewModelOutput.Login.ToString()),
                    new Claim(ClaimTypes.Email, usuarioViewModelOutput.Email.ToString())
                }),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(symmetricSecurityKey,SecurityAlgorithms.HmacSha256Signature)
            };
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var tokenGenerated = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(tokenGenerated);

            return Ok(new
            {
                Token = token,
                Usuario = usuarioViewModelOutput
            });
        }

        [HttpPost]
        [Route("registrar")]
        [ValidacaoModelStateCustomizado]
        public IActionResult Registrar(RegistroViewModelInput loginViewModelInput)
        {
            var optionsBuilder = new DbContextOptionsBuilder<CursoDbContext>();
            optionsBuilder.UseSqlServer("Server=localhost;Database=CURSO;user=sa;password=App@223020");
            CursoDbContext contexto = new CursoDbContext(optionsBuilder.Options);

            var migracoesPendentes = contexto.Database.GetPendingMigrations();
            if (migracoesPendentes.Count() > 0)
            {
                contexto.Database.Migrate();
            }

            var usuario = new Usuario();
            usuario.Login = loginViewModelInput.Login;
            usuario.Senha = loginViewModelInput.Senha;
            usuario.Email = loginViewModelInput.Email;
            contexto.Usuario.Add(usuario);
            contexto.SaveChanges();

            return Created("", loginViewModelInput);
        }
    }

    internal class UsuarioViewModelOutput
    {
        public UsuarioViewModelOutput()
        {
        }

        public int Codigo { get; set; }
        public string Login { get; set; }
        public string Email { get; set; }
    }
}
