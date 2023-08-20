<?php
defined('BASEPATH') or exit('No direct script access allowed');


class Auth extends CI_Controller
{

    public function __constract()
    {
        parent::__construct();
        $this->load->library('form_validation');
    }

    public function index()
    {
        $this->form_validation->set_rules('email', 'Email', 'trim|required|valid_email');
        $this->form_validation->set_rules('password', 'Password', 'trim|required');

        if ($this->form_validation->run() == false) {
            $data['title'] = 'Login Page';
            $this->load->view('templates/auth_header', $data); //untuk header atas
            $this->load->view('auth/login'); // untuk body / isi
            $this->load->view('templates/auth_footer'); // untuk footer bawah
        } else {
            //validasinya success
            $this->_login();
        }
    }

    private function _login()
    {
        // email dan password ini dari name = email name = password
        $email = $this->input->post('email');
        $password = $this->input->post('password');

        // query ke database, cari user yang email sesuai yang kita tulis

        $user = $this->db->get_where('user', ['email' => $email])->row_array();

        // jika usernya ada
        if ($user) {
            // cek password
            if (password_verify($password, $user['password'])) {
                $data = [
                    'email' => $user['email'],
                    'role_id' => $user['role_id']
                ];
                // dipanggil dari session ini
                $this->session->set_userdata($data);

                if ($user['role_id'] == 1) {
                    redirect('admin'); //halaman admin
                } else {
                    redirect('user'); // halaman user
                }
            } else {
                $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Wrong password</div>');
                redirect('auth');
            }

            //jika usernya aktiv
            if ($user['is_active'] == 1) {

            } else { //jika usernya tidak aktiv
                $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">This Email has not been activited!</div>');
                redirect('auth');
            }
        } else { //jika akun email usernya belum ter registrasi
            $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Email is not registrated!.</div>');
            redirect('auth');
        }
    }

    public function registration()
    {
        // harus  tau name nya dan menggunakan required
        //rule refrences (documentation ci3)
        // trim berguna apabila diawal dan di akhir email ada spasi.
        // matches = password sama atau tidak
        // tanda | merupakan rules

        $this->form_validation->set_rules('name', 'Name', 'required|trim');
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[user.email]', [
            'is_unique' => 'This email has already register!'
        ]);
        $this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[3]|matches[password2]', [
            'matches' => 'Password dont match!',
            'min_length' => 'Password too short!'
        ]);
        $this->form_validation->set_rules('password2', 'Password', 'required|trim|matches[password1]');

        if ($this->form_validation->run() == false) {
            $data['title'] = 'WRS User Registration';
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/registration');
            $this->load->view('templates/auth_footer');
        } else {
            $data = [
                'name' => htmlspecialchars($this->input->post('name', true)),
                'email' => htmlspecialchars($this->input->post('email', true)),
                'image' => 'default.jpg',
                'password' => password_hash($this->input->post('password1'), PASSWORD_DEFAULT),
                'role_id' => 2,
                'is_active' => 1,
                'date_created' => time() //time = detik saat itu
            ];

            $this->db->insert('user', $data);

            // membuat alert berhasil registrasi account
            $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">Congratulation, your account hasbeen created. Please Login!</div>');
            redirect('auth');
        }

    }

    public function logout()
    // meng-nonaktifkan email dan role_id
    {
        $this->session->unset_userdata['email'];
        $this->session->unset_userdata['role_id'];

        $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">your have been logged out!</div>');
        redirect('auth');
    }

    public function blocked()
    {
        $this->load->view('auth/blocked');
    }
}