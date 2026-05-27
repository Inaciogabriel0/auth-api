package services

import (
	"fmt"
	"log/slog"
	// "github.com/wneessen/go-mail" // Dependência mockada/comentada se não tiver SMTP configurado
)

type MailService struct{}

func NewMailService() *MailService {
	return &MailService{}
}

// SendPasswordResetEmail envia o e-mail de recuperação.
// Nota: Para um ambiente de produção, configure o client SMTP (ex: go-mail) usando variáveis de ambiente.
func (s *MailService) SendPasswordResetEmail(toEmail, token string) {
	resetLink := fmt.Sprintf("https://seusite.com/reset-password?token=%s", token)

	// Simulação do envio de e-mail no console
	slog.Info("E-mail de recuperação de senha enviado", 
		"destinatario", toEmail, 
		"link_simulado", resetLink,
	)

	// Implementação real (descomente e configure):
	/*
	m := mail.NewMsg()
	if err := m.From("no-reply@seusite.com"); err != nil {
		slog.Error("Erro ao setar remetente", "erro", err)
		return
	}
	if err := m.To(toEmail); err != nil {
		slog.Error("Erro ao setar destinatario", "erro", err)
		return
	}
	m.Subject("Recuperação de Senha")
	m.SetBodyString(mail.TypeTextPlain, fmt.Sprintf("Acesse este link para redefinir sua senha: %s", resetLink))

	c, err := mail.NewClient("smtp.exemplo.com", mail.WithPort(587), mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithUsername("user"), mail.WithPassword("pass"))
	if err != nil {
		slog.Error("Erro ao configurar client SMTP", "erro", err)
		return
	}
	if err := c.DialAndSend(m); err != nil {
		slog.Error("Erro ao enviar email", "erro", err)
	}
	*/
}
